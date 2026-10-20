#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from coverage_identity import CoverageIdentityError, coverage_id
from dangerous_capability_seed import SCANNER_VERSION, SENTINEL_FAMILIES, records_digest, seed_tree
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
DANGEROUS_CAPABILITY_FAMILIES = SENTINEL_FAMILIES
DANGEROUS_CAPABILITY_DISPOSITIONS = {
    "unreviewed",
    "confirmed_finding",
    "high_risk_alert",
    "candidate",
    "negative_closed",
    "coverage_debt",
}
SOURCE_REACHABILITY = {"reachable", "not_reachable", "unknown", "not_applicable"}
REQUIREMENT_CONTEXT_STATUSES = {
    "available",
    "partial",
    "no_match",
    "not_configured",
    "missing_auth",
    "unavailable",
    "not_applicable",
}
REQUIREMENT_CONNECTOR_TERMINAL_STATUSES = {
    "available",
    "no_match",
    "missing_auth",
    "unavailable",
    "missing_tool",
    "timeout",
    "invalid_connector",
}
REQUIREMENT_VERIFICATION_RESULTS = {
    "validated",
    "partial",
    "conflict",
    "rejected",
    "unverified",
}
REQUIREMENT_CONFIDENCE = {"high", "medium", "low"}
REQUIREMENT_SECTIONS = {
    "anchor_summary": dict,
    "query_plan": list,
    "connector_statuses": list,
    "query_log": list,
    "documents": list,
    "conflicts": list,
}
REQUIREMENT_SENSITIVE_FIELDS = {
    "api_key",
    "api_secret",
    "authorization",
    "authorization_header",
    "authorization_headers",
    "client_secret",
    "cookie",
    "credentials",
    "password",
    "refresh_token",
    "secret",
    "secret_value",
    "set_cookie",
    "token",
    "access_token",
}
REQUIREMENT_SOURCE_PAYLOAD_FIELDS = {
    "body",
    "content",
    "document_content",
    "environment_values",
    "full_diff",
    "full_document",
    "raw_document",
    "raw_response",
    "raw_tool_response",
    "response_body",
    "source_code",
}
REQUIREMENT_SECRET_PATTERNS = (
    re.compile(r"\bauthorization\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password)"
        r"\s*[:=]\s*[\"']?[^\s\"',}]{4,}",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"),
)


VERIFICATION_STAGES = {"candidate", "final_record"}
VERIFICATION_INDEPENDENCE = {"fresh_agent", "fresh_pass", "unavailable"}
VERIFICATION_DECISIONS = {"confirmed", "needs_validation", "rejected"}
VERIFICATION_LOCAL_CHECKS = {"none", "bounded_fixture", "sandbox_blocked"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate security-code-audit runtime state.")
    parser.add_argument("run_dir", type=Path)
    parser.add_argument(
        "--target-root",
        type=Path,
        required=True,
        help="Current source tree. The gate re-runs the dangerous capability seed against it.",
    )
    args = parser.parse_args()

    issues = check_state(args.run_dir, target_root=args.target_root)
    coverage = read_jsonl(args.run_dir / "coverage-ledger.jsonl")
    payload = issue_payload(
        "audit_state_check",
        issues,
        {"run_dir": str(args.run_dir), "coverage_rows": len(coverage)},
    )
    emit_json(payload)
    return 1 if payload["status"] == "failed" else 0


def check_state(run_dir: Path, *, target_root: Path | None = None) -> list[Issue]:
    issues: list[Issue] = []
    run_id = ""
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
            else:
                run_id = str(manifest["run_id"])
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
        issues.extend(_check_coverage_row_identity(row, rid))
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
    issues.extend(_check_coverage_identity_duplicates(coverage, str(coverage_path)))
    verification_path = run_dir / "verification-ledger.jsonl"
    if verification_path.exists():
        issues.extend(_check_verification_ledger(read_jsonl(verification_path), str(verification_path)))
    issues.extend(_check_trace_ledger(run_dir, read_jsonl(run_dir / "dangerous-capabilities.jsonl")))
    exploration_path = run_dir / "exploration-ledger.jsonl"
    if not exploration_path.exists():
        issues.append(Issue("STATE030", "exploration-ledger.jsonl is missing", file=str(exploration_path)))
    issues.extend(check_requirements_context(run_dir, run_id=run_id))
    issues.extend(check_remediation_session(run_dir, run_id=run_id))
    issues.extend(_check_dangerous_capabilities(run_dir, target_root=target_root, run_id=run_id))
    return issues


def _check_coverage_row_identity(row: dict[str, Any], record_id: str) -> list[Issue]:
    """Validate the optional canonical identity on one coverage row."""
    coverage_value = row.get("coverage_id")
    canonical_refs = row.get("canonical_refs")
    if coverage_value is None and canonical_refs is None:
        return []

    issues: list[Issue] = []
    if not isinstance(coverage_value, str) or not coverage_value.strip():
        issues.append(Issue("STATE040", "coverage_id must be a non-empty string", record_id=record_id))
    if not isinstance(canonical_refs, dict):
        issues.append(Issue("STATE041", "canonical_refs must be an object when coverage_id is present", record_id=record_id))
        return issues

    required = ("surface", "boundary", "subsystem", "attack_class")
    values: dict[str, str] = {}
    for field in required:
        value = canonical_refs.get(field)
        if not isinstance(value, str) or not value.strip():
            issues.append(Issue("STATE042", f"canonical_refs[{field!r}] must be a non-empty string", record_id=record_id))
        else:
            values[field] = value
    lifecycle = canonical_refs.get("lifecycle")
    if lifecycle is not None and (not isinstance(lifecycle, str) or not lifecycle.strip()):
        issues.append(Issue("STATE042", "canonical_refs['lifecycle'] must be a non-empty string when present", record_id=record_id))
    if issues or not isinstance(coverage_value, str):
        return issues

    try:
        expected = coverage_id(
            surface=values["surface"],
            boundary=values["boundary"],
            subsystem=values["subsystem"],
            attack_class=values["attack_class"],
            lifecycle=lifecycle if isinstance(lifecycle, str) else None,
        )
    except CoverageIdentityError as exc:
        issues.append(Issue("STATE043", f"canonical_refs cannot form a coverage ID: {exc}", record_id=record_id))
    else:
        if coverage_value != expected:
            issues.append(Issue("STATE044", "coverage_id does not match canonical_refs", record_id=record_id))
    return issues

def _check_coverage_identity_duplicates(rows: list[dict[str, Any]], file: str) -> list[Issue]:
    """Reject duplicate canonical IDs while keeping legacy rows compatible."""
    seen: dict[str, str] = {}
    issues: list[Issue] = []
    for row in rows:
        coverage_value = row.get("coverage_id")
        if not isinstance(coverage_value, str) or not coverage_value:
            continue
        record_id = str(row.get("id") or "<missing>")
        previous = seen.get(coverage_value)
        if previous is not None:
            issues.append(
                Issue(
                    "STATE045",
                    f"duplicate coverage_id {coverage_value!r}; first record is {previous}",
                    file=file,
                    record_id=record_id,
                )
            )
        else:
            seen[coverage_value] = record_id
    return issues

def _check_verification_ledger(rows: list[dict[str, Any]], file: str) -> list[Issue]:
    """Validate verifier provenance without requiring it for legacy runs."""
    required = {
        "id",
        "candidate_fingerprint",
        "stage",
        "verifier_id",
        "independence",
        "decision",
        "source_rechecked",
        "local_check",
        "evidence_refs",
        "blockers",
    }
    issues: list[Issue] = []
    seen: set[str] = set()
    for row in rows:
        record_id = str(row.get("id") or "<missing>")
        if "_parse_error" in row:
            issues.append(Issue("STATE050", row["_parse_error"], file=file, line=row.get("_line")))
            continue
        missing = sorted(field for field in required if field not in row)
        if missing:
            issues.append(Issue("STATE051", f"verification row missing fields: {', '.join(missing)}", record_id=record_id))
            continue
        if record_id in seen:
            issues.append(Issue("STATE052", "duplicate verification record id", record_id=record_id))
        seen.add(record_id)
        if row.get("stage") not in VERIFICATION_STAGES:
            issues.append(Issue("STATE054", f"invalid verification stage {row.get('stage')!r}", record_id=record_id))
        if row.get("independence") not in VERIFICATION_INDEPENDENCE:
            issues.append(Issue("STATE055", f"invalid verifier independence {row.get('independence')!r}", record_id=record_id))
        if row.get("decision") not in VERIFICATION_DECISIONS:
            issues.append(Issue("STATE056", f"invalid verification decision {row.get('decision')!r}", record_id=record_id))
        if row.get("local_check") not in VERIFICATION_LOCAL_CHECKS:
            issues.append(Issue("STATE057", f"invalid verifier local_check {row.get('local_check')!r}", record_id=record_id))
        if not isinstance(row.get("source_rechecked"), bool):
            issues.append(Issue("STATE058", "source_rechecked must be boolean", record_id=record_id))
        if not _nonempty_list(row.get("evidence_refs")):
            issues.append(Issue("STATE059", "verification row requires evidence_refs", record_id=record_id))
        if row.get("decision") == "confirmed" and row.get("independence") == "unavailable":
            issues.append(Issue("STATE053", "confirmed verification cannot use unavailable independence", record_id=record_id))
        if row.get("decision") == "confirmed" and (row.get("source_rechecked") is not True or row.get("blockers") != []):
            issues.append(Issue("STATE061", "confirmed verification requires a source recheck and no unresolved blockers", record_id=record_id))
        if row.get("decision") == "needs_validation" and not _nonempty_list(row.get("blockers")):
            issues.append(Issue("STATE060", "needs_validation verification requires blockers", record_id=record_id))
    return issues

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
            issues.append(Issue("STATE037", f"trace_refs do not resolve: {', '.join(missing)}", record_id=str(row.get("id") or "<missing>")))
    return issues

def check_remediation_session(run_dir: Path, *, run_id: str) -> list[Issue]:
    path = run_dir / "remediation-session.json"
    if not path.exists():
        return []
    try:
        loaded = read_json(path)
    except Exception as exc:  # noqa: BLE001
        return [Issue("REMED001", f"remediation-session.json is invalid JSON: {exc}", file=str(path))]
    if not isinstance(loaded, dict):
        return [Issue("REMED002", "remediation session must contain an object", file=str(path))]
    session = loaded
    issues: list[Issue] = []
    if session.get("schema_version") != "remediation-session.v1":
        issues.append(Issue("REMED003", "invalid remediation session schema_version", file=str(path)))
    if run_id and session.get("run_id") != run_id:
        issues.append(Issue("REMED004", "remediation session belongs to a different run_id", file=str(path)))
    if session.get("start_authorization") not in {"prompt", "auto-fix"}:
        issues.append(Issue("REMED005", "invalid remediation start authorization", file=str(path)))
    for field in ("repository_root", "source_branch", "source_head", "repair_branch", "worktree"):
        if not isinstance(session.get(field), str) or not session[field].strip():
            issues.append(Issue("REMED006", f"remediation session requires {field}", file=str(path)))

    review = session.get("review")
    acceptance = session.get("final_acceptance")
    integration = session.get("integration")
    if not isinstance(review, dict):
        issues.append(Issue("REMED007", "remediation review must be an object", file=str(path)))
        review = {}
    if not isinstance(acceptance, dict):
        issues.append(Issue("REMED008", "remediation final_acceptance must be an object", file=str(path)))
        acceptance = {}
    if not isinstance(integration, dict):
        issues.append(Issue("REMED009", "remediation integration must be an object", file=str(path)))
        integration = {}

    accepted = acceptance.get("accepted")
    integration_status = integration.get("status")
    if accepted is True:
        for field in ("reviewed_diff_digest", "receipt_sha256"):
            if not isinstance(acceptance.get(field), str) or not acceptance[field].strip():
                issues.append(Issue("REMED010", f"accepted remediation requires {field}", file=str(path)))
        if review.get("status") != "accepted":
            issues.append(Issue("REMED011", "accepted remediation review status must be accepted", file=str(path)))
    elif accepted is False:
        if integration_status not in {None, "not_started"}:
            issues.append(Issue("REMED012", "unaccepted remediation cannot contain integration progress", file=str(path)))
    else:
        issues.append(Issue("REMED013", "final_acceptance.accepted must be boolean", file=str(path)))

    if review.get("status") in {"pending_user", "accepted"}:
        if not isinstance(review.get("diff_digest"), str) or not review["diff_digest"].strip():
            issues.append(Issue("REMED014", "reviewed remediation requires a diff digest", file=str(path)))
        selected_refs = session.get("selected_finding_refs")
        if not _nonempty_list(selected_refs):
            issues.append(Issue("REMED015", "reviewed remediation requires selected finding refs", file=str(path)))
        else:
            findings = _load_findings_index(run_dir, issues)
            for finding_ref in selected_refs:
                if not isinstance(finding_ref, str) or not finding_ref.strip():
                    issues.append(Issue("REMED019", "selected finding ref must be a non-empty string", file=str(path)))
                    continue
                finding = findings.get(finding_ref)
                if finding is None:
                    issues.append(
                        Issue(
                            "REMED020",
                            f"selected finding ref does not resolve: {finding_ref}",
                            file=str(path),
                            record_id=finding_ref,
                        )
                    )
                    continue
                if finding.get("schema_version") != "finding.v1" or (run_id and finding.get("run_id") != run_id):
                    issues.append(
                        Issue(
                            "REMED021",
                            f"selected finding is not canonical for this run: {finding_ref}",
                            file=str(path),
                            record_id=finding_ref,
                        )
                    )
                if str(finding.get("maturity", "")).strip().casefold() != "confirmed":
                    issues.append(
                        Issue(
                            "REMED022",
                            f"automatic remediation requires a Confirmed finding: {finding_ref}",
                            file=str(path),
                            record_id=finding_ref,
                        )
                    )
                minimal_fix = finding.get("minimal_fix")
                if minimal_fix in (None, "", [], {}) or (isinstance(minimal_fix, str) and not minimal_fix.strip()):
                    issues.append(
                        Issue(
                            "REMED023",
                            f"confirmed finding has no concrete minimum remediation: {finding_ref}",
                            file=str(path),
                            record_id=finding_ref,
                        )
                    )
    if integration_status in {"commit_created", "commit_created_merge_blocked", "merged"}:
        if accepted is not True:
            issues.append(Issue("REMED016", "integration progress requires final acceptance", file=str(path)))
        if not isinstance(integration.get("commit"), str) or not integration["commit"].strip():
            issues.append(Issue("REMED017", "integration progress requires commit hash", file=str(path)))
    if integration_status == "merged" and integration.get("merge") != "fast_forward":
        issues.append(Issue("REMED018", "merged remediation must record fast_forward", file=str(path)))
    return issues


def check_requirements_context(run_dir: Path, *, run_id: str) -> list[Issue]:
    issues: list[Issue] = []
    path = run_dir / "requirements-context.json"
    if not path.exists():
        return [Issue("REQCTX001", "requirements-context.json is missing", file=str(path))]

    try:
        loaded = read_json(path)
    except Exception as exc:  # noqa: BLE001 - stable CLI diagnostics
        return [Issue("REQCTX002", f"requirements-context.json is invalid JSON: {exc}", file=str(path))]
    if not isinstance(loaded, dict):
        return [Issue("REQCTX003", "requirements-context.json must contain an object", file=str(path))]

    context = loaded
    if context.get("schema_version") != "requirements-context.v1":
        issues.append(Issue("REQCTX004", "requirements context schema_version must be 'requirements-context.v1'", file=str(path)))
    if not isinstance(context.get("run_id"), str) or not context["run_id"].strip():
        issues.append(Issue("REQCTX005", "requirements context run_id is missing", file=str(path)))
    elif run_id and context["run_id"] != run_id:
        issues.append(Issue("REQCTX006", "requirements context belongs to a different run_id", file=str(path)))

    status = context.get("status")
    if status not in REQUIREMENT_CONTEXT_STATUSES:
        issues.append(Issue("REQCTX007", f"invalid requirements context status {status!r}", file=str(path)))

    phase = context.get("phase")
    if not isinstance(phase, dict):
        issues.append(Issue("REQCTX008", "requirements context phase must be an object", file=str(path)))
    else:
        for field in (
            "architecture_recon_completed",
            "change_recon_completed",
            "queried_before_security_review",
        ):
            value = phase.get(field)
            if status == "not_applicable":
                if not isinstance(value, bool):
                    issues.append(Issue("REQCTX009", f"requirements context phase.{field} must be boolean", file=str(path)))
            elif value is not True:
                issues.append(Issue("REQCTX009", f"requirements context phase.{field} must be true", file=str(path)))

    for field, expected_type in REQUIREMENT_SECTIONS.items():
        if not isinstance(context.get(field), expected_type):
            issues.append(Issue("REQCTX010", f"requirements context {field} must be a {expected_type.__name__}", file=str(path)))

    connector_statuses = context.get("connector_statuses")
    if isinstance(connector_statuses, list):
        seen_connectors: set[str] = set()
        for index, connector in enumerate(connector_statuses):
            record_id = f"connector_statuses[{index}]"
            if not isinstance(connector, dict):
                issues.append(Issue("REQCTX011", "connector status must be an object", file=str(path), record_id=record_id))
                continue
            connector_id = connector.get("connector_id")
            if not isinstance(connector_id, str) or not connector_id.strip():
                issues.append(Issue("REQCTX012", "connector status requires connector_id", file=str(path), record_id=record_id))
            elif connector_id in seen_connectors:
                issues.append(Issue("REQCTX013", "duplicate connector terminal status", file=str(path), record_id=connector_id))
            else:
                seen_connectors.add(connector_id)
            if connector.get("status") not in REQUIREMENT_CONNECTOR_TERMINAL_STATUSES:
                issues.append(Issue("REQCTX014", f"connector has non-terminal status {connector.get('status')!r}", file=str(path), record_id=str(connector_id or record_id)))

        if status not in {"not_configured", "not_applicable"} and not connector_statuses:
            issues.append(Issue("REQCTX015", "configured requirement context requires connector terminal statuses", file=str(path)))
        if status in {"not_configured", "not_applicable"} and connector_statuses:
            issues.append(Issue("REQCTX016", f"status {status} cannot include attempted connector statuses", file=str(path)))
        connector_states = {
            connector.get("status")
            for connector in connector_statuses
            if isinstance(connector, dict)
        }
        expected_connector_states = {
            "available": {"available"},
            "no_match": {"available", "no_match"},
            "missing_auth": {"missing_auth"},
            "unavailable": {"unavailable", "missing_tool", "timeout", "invalid_connector"},
        }
        expected = expected_connector_states.get(status)
        if expected is not None and connector_states.isdisjoint(expected):
            issues.append(Issue("REQCTX034", f"top-level status {status} is not supported by any connector terminal status", file=str(path)))

    handling = context.get("handling")
    if not isinstance(handling, dict):
        issues.append(Issue("REQCTX017", "requirements context handling must be an object", file=str(path)))
    else:
        if handling.get("source_trust") != "untrusted_external_context":
            issues.append(Issue("REQCTX018", "requirement documents must remain untrusted external context", file=str(path)))
        for field in (
            "may_narrow_audit_scope",
            "no_match_proves_no_requirement",
            "credentials_stored",
            "full_documents_stored",
        ):
            if handling.get(field) is not False:
                issues.append(Issue("REQCTX019", f"requirements context handling.{field} must be false", file=str(path)))

    documents = context.get("documents")
    if isinstance(documents, list):
        seen_documents: set[tuple[str, str]] = set()
        for index, document in enumerate(documents):
            record_id = f"documents[{index}]"
            if not isinstance(document, dict):
                issues.append(Issue("REQCTX020", "requirement document must be an object", file=str(path), record_id=record_id))
                continue
            document_id = document.get("id")
            connector_id = document.get("connector_id")
            if not isinstance(document_id, str) or not document_id.strip():
                issues.append(Issue("REQCTX021", "requirement document requires a stable id", file=str(path), record_id=record_id))
            if not isinstance(connector_id, str) or not connector_id.strip():
                issues.append(Issue("REQCTX022", "requirement document requires connector_id", file=str(path), record_id=record_id))
            if isinstance(document_id, str) and document_id and isinstance(connector_id, str) and connector_id:
                identity = (connector_id, document_id)
                if identity in seen_documents:
                    issues.append(Issue("REQCTX023", "duplicate requirement document identity", file=str(path), record_id=document_id))
                else:
                    seen_documents.add(identity)
            if document.get("confidence") not in REQUIREMENT_CONFIDENCE:
                issues.append(Issue("REQCTX024", f"invalid requirement confidence {document.get('confidence')!r}", file=str(path), record_id=str(document_id or record_id)))
            verification = document.get("verification_result")
            if verification not in REQUIREMENT_VERIFICATION_RESULTS:
                issues.append(Issue("REQCTX025", f"invalid requirement verification_result {verification!r}", file=str(path), record_id=str(document_id or record_id)))
            if not isinstance(document.get("matched_anchors"), list):
                issues.append(Issue("REQCTX026", "requirement document matched_anchors must be a list", file=str(path), record_id=str(document_id or record_id)))
            evidence_refs = document.get("verification_evidence_refs")
            if not isinstance(evidence_refs, list):
                issues.append(Issue("REQCTX027", "verification_evidence_refs must be a list", file=str(path), record_id=str(document_id or record_id)))
            elif verification in {"validated", "partial", "conflict"} and not _nonempty_list(evidence_refs):
                issues.append(Issue("REQCTX028", f"{verification} requirement document requires current evidence refs", file=str(path), record_id=str(document_id or record_id)))

        if status in {"available", "partial"} and not documents:
            issues.append(Issue("REQCTX029", f"status {status} requires at least one requirement document", file=str(path)))
        if status in {"no_match", "not_configured", "missing_auth", "unavailable", "not_applicable"} and documents:
            issues.append(Issue("REQCTX030", f"status {status} cannot include requirement documents", file=str(path)))

    issues.extend(_check_requirement_sensitive_content(context, path))
    return issues


def _check_requirement_sensitive_content(context: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []

    def walk(value: Any, location: str) -> None:
        if isinstance(value, dict):
            for raw_key, child in value.items():
                key = str(raw_key).strip().lower().replace("-", "_")
                child_location = f"{location}.{raw_key}"
                if key in REQUIREMENT_SENSITIVE_FIELDS and child not in (None, "", False, [], {}):
                    issues.append(Issue("REQCTX031", f"credential-bearing field is forbidden at {child_location}", file=str(path)))
                if key in REQUIREMENT_SOURCE_PAYLOAD_FIELDS and child not in (None, "", False, [], {}):
                    issues.append(Issue("REQCTX032", f"raw source or document payload is forbidden at {child_location}", file=str(path)))
                walk(child, child_location)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{location}[{index}]")
            return
        if isinstance(value, str) and any(pattern.search(value) for pattern in REQUIREMENT_SECRET_PATTERNS):
            issues.append(Issue("REQCTX033", f"possible credential material is forbidden at {location}", file=str(path)))

    walk(context, "requirements_context")
    return issues


def _check_dangerous_capabilities(
    run_dir: Path, *, target_root: Path | None, run_id: str
) -> list[Issue]:
    issues: list[Issue] = []
    summary_path = run_dir / "dangerous-capability-census.json"
    seed_path = run_dir / "dangerous-capability-seed.jsonl"
    ledger_path = run_dir / "dangerous-capabilities.jsonl"
    summary: dict[str, Any] | None = None

    if not summary_path.exists():
        issues.append(Issue("DANGER001", "dangerous-capability-census.json is missing", file=str(summary_path)))
    else:
        try:
            loaded = read_json(summary_path)
        except Exception as exc:  # noqa: BLE001
            issues.append(Issue("DANGER002", f"dangerous-capability-census.json is invalid JSON: {exc}", file=str(summary_path)))
        else:
            if not isinstance(loaded, dict):
                issues.append(Issue("DANGER003", "dangerous-capability-census.json must contain an object", file=str(summary_path)))
            else:
                summary = loaded
                if summary.get("schema_version") != "2.0":
                    issues.append(Issue("DANGER004", "dangerous capability census schema_version must be '2.0'; re-seed old runs", file=str(summary_path)))
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
                if summary.get("scanner_version") != SCANNER_VERSION:
                    issues.append(Issue("DANGER027", "census scanner_version is stale; re-seed the target", file=str(summary_path)))
                if not isinstance(summary.get("snapshot_digest"), str) or not summary["snapshot_digest"]:
                    issues.append(Issue("DANGER028", "census requires a source snapshot_digest", file=str(summary_path)))
                if not isinstance(summary.get("records_digest"), str) or not summary["records_digest"]:
                    issues.append(Issue("DANGER029", "census requires a raw records_digest", file=str(summary_path)))
                if summary.get("scan_issues") not in ([], None):
                    issues.append(Issue("DANGER034", "census contains unresolved scan issues", file=str(summary_path)))

    if not seed_path.exists():
        issues.append(Issue("DANGER035", "dangerous-capability-seed.jsonl is missing", file=str(seed_path)))
        seed_rows: list[dict[str, Any]] = []
    else:
        seed_rows = read_jsonl(seed_path)
        for row in seed_rows:
            if "_parse_error" in row:
                issues.append(Issue("DANGER036", row["_parse_error"], file=str(seed_path), line=row.get("_line")))

    if target_root is None:
        issues.append(Issue("DANGER033", "target_root is required for source-bound final validation"))
        fresh_payload: dict[str, Any] | None = None
    else:
        fresh_payload = seed_tree(target_root)
        if fresh_payload.get("status") != "ok":
            message = "; ".join(str(item.get("message")) for item in fresh_payload.get("issues", []))
            issues.append(Issue("DANGER037", f"fresh source seed failed: {message or 'unknown scanner failure'}", file=str(target_root)))

    if not ledger_path.exists():
        issues.append(Issue("DANGER010", "dangerous-capabilities.jsonl is missing", file=str(ledger_path)))
        rows: list[dict[str, Any]] = []
    else:
        rows = read_jsonl(ledger_path)

    ledger_by_id: dict[str, dict[str, Any]] = {}
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
        if run_id and row.get("run_id") != run_id:
            issues.append(Issue("DANGER038", "dangerous capability row belongs to a different run_id", record_id=rid))
        if rid in ledger_by_id:
            issues.append(Issue("DANGER039", "duplicate dangerous capability id", record_id=rid))
        else:
            ledger_by_id[rid] = row
        family = row.get("family")
        if not isinstance(family, str) or not family:
            issues.append(Issue("DANGER014", "dangerous capability row requires family", record_id=rid))
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

    seed_by_id = _index_records(seed_rows, issues, "DANGER040", seed_path)
    for seed_id, seed_row in seed_by_id.items():
        ledger_row = ledger_by_id.get(seed_id)
        if ledger_row is None:
            issues.append(Issue("DANGER041", "source-seeded dangerous capability is missing from ledger", record_id=seed_id))
            continue
        for field in ("family", "kind", "location", "source_digest"):
            if ledger_row.get(field) != seed_row.get(field):
                issues.append(Issue("DANGER042", f"ledger changed immutable seed field {field}", record_id=seed_id))
    for ledger_id, ledger_row in ledger_by_id.items():
        if ledger_id not in seed_by_id and ledger_row.get("origin") != "manual":
            issues.append(Issue("DANGER043", "non-seeded ledger row must declare origin=manual", record_id=ledger_id))

    if summary is not None:
        expected_total = summary.get("discovered_total")
        if isinstance(expected_total, int) and expected_total != len(seed_rows):
            issues.append(Issue("DANGER030", "discovered_total does not equal raw seed row count", file=str(summary_path)))
        if summary.get("records_digest") != records_digest(seed_rows):
            issues.append(Issue("DANGER044", "raw seed digest does not match census summary", file=str(seed_path)))
        family_totals = summary.get("family_totals")
        if isinstance(family_totals, dict):
            seeded_family_totals: dict[str, int] = {family: 0 for family in DANGEROUS_CAPABILITY_FAMILIES}
            for row in seed_rows:
                family = row.get("family")
                if isinstance(family, str):
                    seeded_family_totals[family] = seeded_family_totals.get(family, 0) + 1
            all_families = set(family_totals) | set(seeded_family_totals)
            for family in sorted(all_families):
                if family_totals.get(family, 0) != seeded_family_totals.get(family, 0):
                    issues.append(Issue("DANGER031", f"family total does not reconcile for {family}", file=str(summary_path)))
            numeric_totals = [value for value in family_totals.values() if isinstance(value, int) and value >= 0]
            if len(numeric_totals) == len(family_totals) and isinstance(expected_total, int):
                if sum(numeric_totals) != expected_total:
                    issues.append(Issue("DANGER032", "sum of family_totals does not equal discovered_total", file=str(summary_path)))
        if target_root is not None and summary.get("root") != str(target_root.resolve()):
            issues.append(Issue("DANGER045", "census root does not match the validated target root", file=str(summary_path)))
        if fresh_payload is not None and fresh_payload.get("status") == "ok":
            if summary.get("snapshot_digest") != fresh_payload.get("snapshot_digest"):
                issues.append(Issue("DANGER046", "target source changed after the stored seed was created", file=str(summary_path)))
            fresh_rows = fresh_payload.get("records", [])
            if records_digest(seed_rows) != records_digest(fresh_rows):
                issues.append(Issue("DANGER047", "stored seed does not match a fresh source scan", file=str(seed_path)))

    issues.extend(_check_reference_integrity(run_dir, rows, run_id=run_id))
    return issues


def _index_records(
    rows: list[dict[str, Any]], issues: list[Issue], duplicate_code: str, path: Path
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        rid = row.get("id")
        if not isinstance(rid, str) or not rid:
            continue
        if rid in index:
            issues.append(Issue(duplicate_code, "duplicate record id", file=str(path), record_id=rid))
        else:
            index[rid] = row
    return index


def _check_reference_integrity(run_dir: Path, rows: list[dict[str, Any]], *, run_id: str) -> list[Issue]:
    issues: list[Issue] = []
    evidence = _load_reference_index(run_dir / "evidence-observations.jsonl", issues)
    traces = _load_reference_index(run_dir / "trace-ledger.jsonl", issues)
    coverage = _load_reference_index(run_dir / "coverage-ledger.jsonl", issues)
    findings = _load_findings_index(run_dir, issues)

    for row in rows:
        if "_parse_error" in row:
            continue
        rid = str(row.get("id") or "<missing>")
        _resolve_refs(row.get("evidence_refs"), evidence, "evidence", rid, run_id, issues)
        disposition = row.get("disposition")
        if disposition in {"confirmed_finding", "high_risk_alert", "candidate", "negative_closed"}:
            _resolve_refs(row.get("trace_refs"), traces, "trace", rid, run_id, issues)
        if disposition == "confirmed_finding":
            _resolve_refs(row.get("finding_refs"), findings, "finding", rid, run_id, issues)
        if disposition == "coverage_debt":
            combined_debt = dict(evidence)
            combined_debt.update(coverage)
            _resolve_refs(row.get("coverage_debt_refs"), combined_debt, "coverage debt", rid, run_id, issues)
    return issues


def _load_reference_index(path: Path, issues: list[Issue]) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    rows = read_jsonl(path)
    for row in rows:
        if "_parse_error" in row:
            issues.append(Issue("DANGER048", row["_parse_error"], file=str(path), line=row.get("_line")))
    return _index_records(rows, issues, "DANGER049", path)


def _load_findings_index(run_dir: Path, issues: list[Issue]) -> dict[str, dict[str, Any]]:
    manifest_path = run_dir / "manifest.json"
    path: Path | None = None
    if manifest_path.exists():
        try:
            manifest = read_json(manifest_path)
        except Exception:  # already reported by the main state validator
            manifest = {}
        configured = manifest.get("findings_path") if isinstance(manifest, dict) else None
        if isinstance(configured, str) and configured:
            candidate = Path(configured)
            path = candidate if candidate.is_absolute() else run_dir / candidate
    if path is None:
        candidates = sorted(run_dir.parent.glob("*-findings.jsonl"))
        if len(candidates) == 1:
            path = candidates[0]
    if path is None:
        return {}
    rows = read_jsonl(path)
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        identities = {
            identity
            for identity in (row.get("id"), row.get("fingerprint"))
            if isinstance(identity, str) and identity
        }
        for ref in identities:
            if ref in index:
                issues.append(Issue("DANGER049", "duplicate finding reference", file=str(path), record_id=ref))
            else:
                index[ref] = row
    return index


def _resolve_refs(
    refs: Any,
    index: dict[str, dict[str, Any]],
    ref_type: str,
    owner_id: str,
    run_id: str,
    issues: list[Issue],
) -> None:
    if not _nonempty_list(refs):
        issues.append(Issue("DANGER050", f"dangerous capability requires resolvable {ref_type} refs", record_id=owner_id))
        return
    for ref in refs:
        if not isinstance(ref, str) or not ref.strip():
            continue
        target = index.get(ref)
        if target is None:
            issues.append(Issue("DANGER051", f"{ref_type} ref does not resolve: {ref}", record_id=owner_id))
        elif run_id and target.get("run_id") != run_id:
            issues.append(Issue("DANGER052", f"{ref_type} ref belongs to a different run_id: {ref}", record_id=owner_id))


def _nonempty_list(value: Any) -> bool:
    return isinstance(value, list) and any(isinstance(item, str) and item.strip() for item in value)


if __name__ == "__main__":
    raise SystemExit(main())
