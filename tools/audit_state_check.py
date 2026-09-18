#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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
DANGEROUS_CAPABILITY_FAMILIES = {
    "dynamic_code_evaluation",
    "shell_command_execution",
    "shell_code_loading",
    "signing_material",
    "signed_state_consumer",
}
DANGEROUS_CAPABILITY_DISPOSITIONS = {
    "unreviewed",
    "confirmed_finding",
    "high_risk_alert",
    "candidate",
    "negative_closed",
    "coverage_debt",
}
SOURCE_REACHABILITY = {"reachable", "not_reachable", "unknown", "not_applicable"}


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
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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
    dangerous_issues, dangerous_rows = _check_dangerous_capabilities(run_dir)
    issues.extend(dangerous_issues)
    issues.extend(_check_trace_ledger(run_dir, dangerous_rows))
    exploration_path = run_dir / "exploration-ledger.jsonl"
    if not exploration_path.exists():
        issues.append(Issue("STATE030", "exploration-ledger.jsonl is missing", file=str(exploration_path)))
    return issues


def _check_dangerous_capabilities(run_dir: Path) -> tuple[list[Issue], list[dict[str, Any]]]:
    issues: list[Issue] = []
    summary_path = run_dir / "dangerous-capability-census.json"
    ledger_path = run_dir / "dangerous-capabilities.jsonl"
    summary: dict[str, Any] | None = None

    if not summary_path.exists():
        issues.append(Issue("DANGER001", "dangerous-capability-census.json is missing", file=str(summary_path)))
    else:
        try:
            loaded = read_json(summary_path)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            issues.append(Issue("DANGER002", f"dangerous-capability-census.json is invalid JSON: {exc}", file=str(summary_path)))
        else:
            if not isinstance(loaded, dict):
                issues.append(Issue("DANGER003", "dangerous-capability-census.json must contain an object", file=str(summary_path)))
            else:
                summary = loaded
                if summary.get("schema_version") != "1.0":
                    issues.append(Issue("DANGER004", "dangerous capability census schema_version must be '1.0'", file=str(summary_path)))
                if summary.get("census_completed") is not True:
                    issues.append(Issue("DANGER005", "dangerous capability census is not marked complete", file=str(summary_path)))
                required = summary.get("required_families")
                required_set = {item for item in required if isinstance(item, str)} if isinstance(required, list) else set()
                if not isinstance(required, list) or not DANGEROUS_CAPABILITY_FAMILIES.issubset(required_set):
                    missing = sorted(DANGEROUS_CAPABILITY_FAMILIES - required_set)
                    issues.append(Issue("DANGER006", f"census required_families missing sentinels: {', '.join(missing)}", file=str(summary_path)))
                discovered_total = summary.get("discovered_total")
                if not isinstance(discovered_total, int) or discovered_total < 0:
                    issues.append(Issue("DANGER007", "census discovered_total must be a non-negative integer", file=str(summary_path)))
                family_totals = summary.get("family_totals")
                if not isinstance(family_totals, dict):
                    issues.append(Issue("DANGER008", "census family_totals must be an object", file=str(summary_path)))
                else:
                    for family in DANGEROUS_CAPABILITY_FAMILIES:
                        value = family_totals.get(family)
                        if not isinstance(value, int) or value < 0:
                            issues.append(Issue("DANGER009", f"family_totals[{family!r}] must be a non-negative integer", file=str(summary_path)))
                if not isinstance(summary.get("scope"), str) or not summary["scope"].strip():
                    issues.append(Issue("DANGER025", "census scope must be a non-empty string", file=str(summary_path)))
                if not isinstance(summary.get("files_considered"), int) or summary["files_considered"] <= 0:
                    issues.append(Issue("DANGER026", "census files_considered must be a positive integer", file=str(summary_path)))
                if not _nonempty_list(summary.get("manual_search_evidence_refs")):
                    issues.append(Issue("DANGER027", "census requires manual_search_evidence_refs", file=str(summary_path)))

    if not ledger_path.exists():
        issues.append(Issue("DANGER010", "dangerous-capabilities.jsonl is missing", file=str(ledger_path)))
        rows: list[dict[str, Any]] = []
    else:
        rows = read_jsonl(ledger_path)

    actual_family_totals: dict[str, int] = {}
    for row in rows:
        rid = str(row.get("id") or "<missing>")
        if "_parse_error" in row:
            issues.append(Issue("DANGER011", row["_parse_error"], file=str(ledger_path), line=row.get("_line")))
            continue
        missing = sorted(field for field in COMMON_RECORD_FIELDS if field not in row)
        if missing:
            issues.append(Issue("DANGER012", f"dangerous capability row missing fields: {', '.join(missing)}", record_id=rid))
        if row.get("freshness_status") not in FRESHNESS:
            issues.append(Issue("DANGER013", f"invalid freshness_status {row.get('freshness_status')!r}", record_id=rid))
        family = row.get("family")
        if not isinstance(family, str) or not family:
            issues.append(Issue("DANGER014", "dangerous capability row requires family", record_id=rid))
        else:
            actual_family_totals[family] = actual_family_totals.get(family, 0) + 1
        for field in ("kind", "location"):
            if not isinstance(row.get(field), str) or not row[field].strip():
                issues.append(Issue("DANGER015", f"dangerous capability row requires {field}", record_id=rid))
        if row.get("source_reachability") not in SOURCE_REACHABILITY:
            issues.append(Issue("DANGER016", f"invalid source_reachability {row.get('source_reachability')!r}", record_id=rid))
        disposition = row.get("disposition")
        if disposition not in DANGEROUS_CAPABILITY_DISPOSITIONS:
            issues.append(Issue("DANGER017", f"invalid disposition {disposition!r}", record_id=rid))
        elif disposition == "unreviewed":
            issues.append(Issue("DANGER018", "dangerous capability remains unreviewed", record_id=rid))
        elif disposition == "confirmed_finding" and not _nonempty_list(row.get("finding_refs")):
            issues.append(Issue("DANGER019", "confirmed_finding requires finding_refs", record_id=rid))
        elif disposition == "negative_closed" and not _nonempty_list(row.get("negative_evidence")):
            issues.append(Issue("DANGER020", "negative_closed requires concrete negative_evidence", record_id=rid))
        elif disposition == "coverage_debt" and not _nonempty_list(row.get("coverage_debt_refs")):
            issues.append(Issue("DANGER021", "coverage_debt requires coverage_debt_refs", record_id=rid))
        if disposition in {"confirmed_finding", "high_risk_alert", "candidate", "coverage_debt"}:
            if not _nonempty_list(row.get("report_refs")):
                issues.append(Issue("DANGER022", f"{disposition} requires stable report_refs", record_id=rid))
        if family == "dynamic_code_evaluation" and row.get("source_reachability") in {"reachable", "unknown"}:
            if disposition == "negative_closed":
                issues.append(Issue("DANGER023", "reachable or unresolved dynamic evaluation cannot be negative-closed while the occurrence remains live", record_id=rid))
        if family in DANGEROUS_CAPABILITY_FAMILIES:
            if disposition in {"confirmed_finding", "high_risk_alert", "candidate", "negative_closed"} and not _nonempty_list(row.get("trace_refs")):
                issues.append(Issue("DANGER024", f"{family} disposition requires trace_refs", record_id=rid))

    if summary is not None:
        expected_total = summary.get("discovered_total")
        if isinstance(expected_total, int) and expected_total != len(rows):
            issues.append(Issue("DANGER030", "discovered_total does not equal dangerous-capabilities.jsonl row count", file=str(summary_path)))
        family_totals = summary.get("family_totals")
        if isinstance(family_totals, dict):
            all_families = set(family_totals) | set(actual_family_totals)
            for family in sorted(all_families):
                if family_totals.get(family, 0) != actual_family_totals.get(family, 0):
                    issues.append(Issue("DANGER031", f"family total does not reconcile for {family}", file=str(summary_path)))
            numeric_totals = [value for value in family_totals.values() if isinstance(value, int) and value >= 0]
            if len(numeric_totals) == len(family_totals) and isinstance(expected_total, int):
                if sum(numeric_totals) != expected_total:
                    issues.append(Issue("DANGER032", "sum of family_totals does not equal discovered_total", file=str(summary_path)))
    return issues, rows


def _check_trace_ledger(run_dir: Path, dangerous_rows: list[dict[str, Any]]) -> list[Issue]:
    """Ensure evidence references resolve to structured, usable trace checkpoints."""
    issues: list[Issue] = []
    trace_path = run_dir / "trace-ledger.jsonl"
    if not trace_path.exists():
        issues.append(Issue("STATE031", "trace-ledger.jsonl is missing", file=str(trace_path)))
        return issues

    traces = read_jsonl(trace_path)
    trace_ids: set[str] = set()
    required_trace_fields = COMMON_RECORD_FIELDS | {
        "entry_point",
        "source",
        "sink_or_transition",
        "status",
    }
    for trace in traces:
        rid = str(trace.get("id") or "<missing>")
        if "_parse_error" in trace:
            issues.append(Issue("STATE032", trace["_parse_error"], file=str(trace_path), line=trace.get("_line")))
            continue
        trace_ids.add(rid)
        missing = sorted(field for field in required_trace_fields if field not in trace)
        if missing:
            issues.append(Issue("STATE033", f"trace row missing fields: {', '.join(missing)}", record_id=rid))
        if trace.get("freshness_status") not in FRESHNESS:
            issues.append(Issue("STATE034", f"invalid trace freshness_status {trace.get('freshness_status')!r}", record_id=rid))
        if not _nonempty_list(trace.get("evidence_refs")):
            issues.append(Issue("STATE035", "trace row requires evidence_refs", record_id=rid))
        if not isinstance(trace.get("status"), str) or not trace["status"].strip():
            issues.append(Issue("STATE036", "trace row requires a non-empty status", record_id=rid))

    trace_dispositions = {"confirmed_finding", "high_risk_alert", "candidate", "negative_closed"}
    for row in dangerous_rows:
        if row.get("disposition") not in trace_dispositions:
            continue
        refs = row.get("trace_refs")
        if not _nonempty_list(refs):
            continue
        missing = [ref for ref in refs if ref not in trace_ids]
        if missing:
            issues.append(Issue("DANGER033", f"trace_refs do not resolve: {', '.join(missing)}", record_id=str(row.get("id") or "<missing>")))
    return issues


def _nonempty_list(value: Any) -> bool:
    return isinstance(value, list) and any(isinstance(item, str) and item.strip() for item in value)


if __name__ == "__main__":
    raise SystemExit(main())
