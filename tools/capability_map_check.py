#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from security_audit_tools.capability import (
    ALLOWED_CLAIMS,
    ALLOWED_EFFECTS,
    ALLOWED_GATE_STRENGTHS,
    ALLOWED_PATH_STATUS,
    ALLOWED_TRIGGERS,
    CLAIM_BLOCKED_EFFECTS,
    DANGEROUS_EFFECTS,
)
from security_audit_tools.common import Issue, emit_json, issue_payload, read_jsonl


REQUIRED_CAPABILITY_FIELDS = {
    "id",
    "scope",
    "effects",
    "sources",
    "sinks",
    "resources",
    "evidence_refs",
    "trigger",
    "gate",
    "gate_strength",
    "path_status",
    "freshness_status",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate advisory capability-map records.")
    parser.add_argument("--capabilities", type=Path, required=True)
    parser.add_argument("--raw-observations", type=Path)
    parser.add_argument("--paths", type=Path)
    parser.add_argument("--claims", type=Path)
    args = parser.parse_args()

    capabilities = read_jsonl(args.capabilities)
    raw = read_jsonl(args.raw_observations)
    paths = read_jsonl(args.paths)
    claims = read_jsonl(args.claims)
    issues = check_capability_map(capabilities, raw, paths, claims)
    payload = issue_payload(
        "capability_map_check",
        issues,
        {
            "capabilities": len(capabilities),
            "raw_observations": len(raw),
            "capability_paths": len(paths),
            "capability_claims": len(claims),
        },
    )
    emit_json(payload)
    return 1 if payload["status"] == "failed" else 0


def check_capability_map(
    capabilities: list[dict[str, Any]],
    raw: list[dict[str, Any]],
    paths: list[dict[str, Any]],
    claims: list[dict[str, Any]],
) -> list[Issue]:
    issues: list[Issue] = []
    raw_ids = {record.get("id") for record in raw if record.get("id")}
    seen: set[str] = set()

    for record in capabilities:
        rid = str(record.get("id") or "<missing>")
        if "_parse_error" in record:
            issues.append(Issue("CAP000", record["_parse_error"], line=record.get("_line")))
            continue
        missing = sorted(field for field in REQUIRED_CAPABILITY_FIELDS if field not in record)
        if missing:
            issues.append(
                Issue("CAP001", f"capability missing required fields: {', '.join(missing)}", record_id=rid)
            )
        if rid in seen:
            issues.append(Issue("CAP002", f"duplicate capability id {rid!r}", record_id=rid))
        seen.add(rid)
        _check_enum_list(issues, record, "effects", ALLOWED_EFFECTS, "CAP003")
        _check_enum_scalar(issues, record, "trigger", ALLOWED_TRIGGERS, "CAP006")
        _check_enum_scalar(issues, record, "gate_strength", ALLOWED_GATE_STRENGTHS, "CAP007")
        _check_enum_scalar(issues, record, "path_status", ALLOWED_PATH_STATUS, "CAP008")
        refs = record.get("evidence_refs")
        if not isinstance(refs, list) or not refs:
            issues.append(Issue("CAP004", "capability has no evidence_refs", record_id=rid))
        elif raw_ids:
            for ref in refs:
                if ref not in raw_ids:
                    issues.append(
                        Issue("CAP004", f"evidence ref {ref!r} is not present in raw observations", record_id=rid)
                    )
        effects = set(record.get("effects") or [])
        path_status = record.get("path_status")
        gate_strength = record.get("gate_strength")
        if effects & DANGEROUS_EFFECTS and not path_status:
            issues.append(
                Issue("CAP005", "dangerous capability lacks path_status", record_id=rid)
            )
        if effects & DANGEROUS_EFFECTS and gate_strength == "none" and path_status == "confirmed":
            issues.append(
                Issue(
                    "CAP009",
                    "confirmed dangerous capability has no gate; verify this is intentional and evidence-backed",
                    severity="warning",
                    record_id=rid,
                )
            )

    issues.extend(_check_claims(capabilities, claims))
    return issues


def _check_enum_list(
    issues: list[Issue], record: dict[str, Any], field: str, allowed: set[str], code: str
) -> None:
    rid = str(record.get("id") or "<missing>")
    value = record.get(field)
    if not isinstance(value, list):
        issues.append(Issue(code, f"{field} must be a list", record_id=rid))
        return
    for item in value:
        if item not in allowed:
            issues.append(Issue(code, f"{field} contains unknown enum {item!r}", record_id=rid))


def _check_enum_scalar(
    issues: list[Issue], record: dict[str, Any], field: str, allowed: set[str], code: str
) -> None:
    value = record.get(field)
    if value is None:
        return
    if value not in allowed:
        issues.append(
            Issue(code, f"{field} contains unknown enum {value!r}", record_id=str(record.get("id") or "<missing>"))
        )


def _check_claims(capabilities: list[dict[str, Any]], claims: list[dict[str, Any]]) -> list[Issue]:
    issues: list[Issue] = []
    claim_values: list[str] = []
    for claim in claims:
        value = claim.get("claim")
        if value not in ALLOWED_CLAIMS:
            issues.append(
                Issue("CAP021", f"claim contains unknown enum {value!r}", record_id=str(claim.get("id") or "<missing>"))
            )
            continue
        claim_values.append(value)
    if not claim_values:
        return issues
    all_effects = {
        effect
        for capability in capabilities
        if capability.get("path_status") not in {"negative_evidence", "blocked"}
        for effect in capability.get("effects", [])
        if isinstance(capability.get("effects"), list)
    }
    for claim in sorted(set(claim_values)):
        blocked = CLAIM_BLOCKED_EFFECTS.get(claim, set())
        overlap = sorted(all_effects & blocked)
        if overlap:
            issues.append(
                Issue(
                    "CAP020",
                    f"claim {claim!r} conflicts with observed effects: {', '.join(overlap)}",
                )
            )
    return issues


if __name__ == "__main__":
    raise SystemExit(main())
