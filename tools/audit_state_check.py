#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from security_audit_tools.common import Issue, emit_json, issue_payload, read_json, read_jsonl


COMMON_RECORD_FIELDS = {"id", "run_id", "scope", "owner", "freshness_status", "evidence_refs"}
FRESHNESS = {
    "fresh_current",
    "comparable",
    "stale_needs_recheck",
    "invalidated",
    "not_applicable",
}
COUNT_FIELDS = {
    "applicable_total",
    "reviewed",
    "partial",
    "blocked",
    "invalidated",
    "time_boxed",
    "function_entries_total",
    "function_chains_recorded",
    "explicit_function_chain_debt",
    "debt_total",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate security-code-audit runtime state.")
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()

    issues = check_state(args.run_dir)
    coverage = read_jsonl(args.run_dir / "coverage-ledger.jsonl")
    payload = issue_payload(
        "audit_state_check",
        issues,
        {"run_dir": str(args.run_dir), "coverage_rows": len(coverage)},
    )
    emit_json(payload)
    return 1 if payload["status"] == "failed" else 0


def check_state(run_dir: Path) -> list[Issue]:
    issues: list[Issue] = []
    manifest_path = run_dir / "manifest.json"
    change_path = run_dir / "current-change-context.json"
    if not manifest_path.exists():
        issues.append(Issue("STATE001", "manifest.json is missing", file=str(manifest_path)))
    else:
        try:
            manifest = read_json(manifest_path)
        except Exception as exc:  # noqa: BLE001 - stable CLI diagnostics
            issues.append(Issue("STATE002", f"manifest.json is invalid JSON: {exc}", file=str(manifest_path)))
        else:
            if manifest.get("schema_version") != "2.0":
                issues.append(Issue("STATE003", "manifest schema_version must be '2.0'", file=str(manifest_path)))
            if not manifest.get("run_id"):
                issues.append(Issue("STATE004", "manifest run_id is missing", file=str(manifest_path)))
    if not change_path.exists():
        issues.append(Issue("STATE010", "current-change-context.json is missing", file=str(change_path)))
    else:
        try:
            change = read_json(change_path)
        except Exception as exc:  # noqa: BLE001
            issues.append(Issue("STATE011", f"current-change-context.json is invalid JSON: {exc}", file=str(change_path)))
        else:
            if not (
                change.get("fresh_recon_completed")
                or change.get("current_recon_completed")
                or change.get("fresh_current_recon")
            ):
                issues.append(Issue("STATE012", "fresh current recon is not marked complete", file=str(change_path)))

    coverage_path = run_dir / "coverage-ledger.jsonl"
    coverage = read_jsonl(coverage_path)
    for row in coverage:
        rid = str(row.get("id") or "<missing>")
        if "_parse_error" in row:
            issues.append(Issue("STATE000", row["_parse_error"], file=str(coverage_path), line=row.get("_line")))
            continue
        missing = sorted(field for field in COMMON_RECORD_FIELDS if field not in row)
        if missing:
            issues.append(Issue("STATE013", f"coverage row missing fields: {', '.join(missing)}", record_id=rid))
        if row.get("freshness_status") not in FRESHNESS:
            issues.append(Issue("STATE014", f"invalid freshness_status {row.get('freshness_status')!r}", record_id=rid))
        for field in COUNT_FIELDS:
            if field not in row:
                issues.append(Issue("STATE015", f"coverage row missing count field {field}", record_id=rid))
                continue
            if not isinstance(row[field], int) or row[field] < 0:
                issues.append(Issue("STATE016", f"coverage count {field} must be a non-negative integer", record_id=rid))
        if all(field in row and isinstance(row[field], int) for field in ("function_entries_total", "function_chains_recorded", "explicit_function_chain_debt")):
            expected = row["function_chains_recorded"] + row["explicit_function_chain_debt"]
            if row["function_entries_total"] != expected:
                issues.append(
                    Issue(
                        "STATE020",
                        "function-chain counts do not reconcile: function_entries_total must equal function_chains_recorded + explicit_function_chain_debt",
                        record_id=rid,
                    )
                )
    return issues


if __name__ == "__main__":
    raise SystemExit(main())
