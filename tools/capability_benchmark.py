#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from capability_map_check import check_capability_map
from capability_map_seed import seed
from security_audit_tools.common import emit_json, positive_int, write_jsonl


EXPECTED = {
    "skill-risky": {
        "effects": {
            "browser_profile_access",
            "env_read",
            "fs_read",
            "fs_write",
            "net_read",
            "persistence",
            "proc_exec",
        },
        "claims": {"local_only", "read_only"},
        "unmapped": True,
        "contradictions": True,
    },
    "skill-benign": {
        "effects": set(),
        "claims": {"read_only"},
        "unmapped": False,
        "contradictions": False,
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local capability-assurance benchmark.")
    parser.add_argument("fixture_root", type=Path)
    parser.add_argument("--out", type=Path, help="Optional directory for per-case seeded outputs.")
    parser.add_argument("--max-file-bytes", type=positive_int, default=1_000_000)
    args = parser.parse_args()

    payload = run_benchmark(args.fixture_root, out=args.out, max_file_bytes=args.max_file_bytes)
    emit_json(payload)
    return 0 if payload["status"] == "ok" else 1


def run_benchmark(fixture_root: Path, *, out: Path | None, max_file_bytes: int) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    expected_effect_total = 0
    found_effect_total = 0
    unmapped_expected = 0
    unmapped_detected = 0
    contradiction_expected = 0
    contradiction_detected = 0

    for case_dir in sorted(path for path in fixture_root.iterdir() if path.is_dir()):
        expected = EXPECTED.get(case_dir.name, {"effects": set(), "claims": set()})
        raw, capabilities, paths, claims, unmapped = seed(case_dir, max_file_bytes=max_file_bytes)
        issues = check_capability_map(capabilities, raw, paths, claims)
        effects_found = {
            effect
            for capability in capabilities
            for effect in capability.get("effects", [])
            if isinstance(capability.get("effects"), list)
        }
        claims_found = {
            claim.get("claim") for claim in claims if isinstance(claim.get("claim"), str)
        }
        expected_effects = set(expected.get("effects", set()))
        expected_claims = set(expected.get("claims", set()))
        found_expected = expected_effects & effects_found
        missing_effects = sorted(expected_effects - effects_found)
        missing_claims = sorted(expected_claims - claims_found)
        contradiction_count = len([issue for issue in issues if issue.code == "CAP020"])
        negative_evidence_count = len(
            [
                capability
                for capability in capabilities
                if capability.get("path_status") == "negative_evidence"
            ]
        )

        expected_effect_total += len(expected_effects)
        found_effect_total += len(found_expected)
        if expected.get("unmapped"):
            unmapped_expected += 1
            if unmapped:
                unmapped_detected += 1
        if expected.get("contradictions"):
            contradiction_expected += 1
            if contradiction_count:
                contradiction_detected += 1

        if out:
            target = out / case_dir.name
            write_jsonl(target / "raw-observations.jsonl", raw)
            write_jsonl(target / "capabilities.jsonl", capabilities)
            write_jsonl(target / "capability-paths.jsonl", paths)
            write_jsonl(target / "capability-claims.jsonl", claims)
            write_jsonl(target / "unmapped-signals.jsonl", unmapped)
            write_jsonl(
                target / "capability-check-issues.jsonl",
                [issue.to_dict() for issue in issues],
            )

        cases.append(
            {
                "case": case_dir.name,
                "effects_expected": sorted(expected_effects),
                "effects_found": sorted(effects_found),
                "effects_missing": missing_effects,
                "claims_expected": sorted(expected_claims),
                "claims_found": sorted(claims_found),
                "claims_missing": missing_claims,
                "raw_observations": len(raw),
                "capabilities": len(capabilities),
                "negative_evidence_capabilities": negative_evidence_count,
                "unmapped_signals": len(unmapped),
                "claim_contradictions": contradiction_count,
                "checker_errors": len([issue for issue in issues if issue.severity == "error"]),
            }
        )

    effect_recall = (
        found_effect_total / expected_effect_total if expected_effect_total else 1.0
    )
    status = "ok"
    if effect_recall < 0.8:
        status = "failed"
    if unmapped_detected < unmapped_expected:
        status = "failed"
    if contradiction_detected < contradiction_expected:
        status = "failed"

    return {
        "tool": "capability_benchmark",
        "status": status,
        "summary": {
            "cases": len(cases),
            "effect_recall": round(effect_recall, 4),
            "expected_effects": expected_effect_total,
            "expected_effects_found": found_effect_total,
            "unmapped_cases_expected": unmapped_expected,
            "unmapped_cases_detected": unmapped_detected,
            "contradiction_cases_expected": contradiction_expected,
            "contradiction_cases_detected": contradiction_detected,
        },
        "cases": cases,
        "open_world_notice": (
            "This benchmark checks deterministic seeding/checking behavior only. It is not a "
            "safety proof and does not bound LLM/human observations."
        ),
    }


if __name__ == "__main__":
    raise SystemExit(main())
