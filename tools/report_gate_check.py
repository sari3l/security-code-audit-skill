#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from security_audit_tools.common import Issue, emit_json, issue_payload, read_jsonl
from security_audit_tools.reporting import MARKDOWN_FIELD_ALIASES, MARKDOWN_REQUIRED_FIELDS, parse_markdown_findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Check report maturity and routing gates.")
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--run-dir",
        type=Path,
        help="Optional audit-state directory used to reconcile dangerous capability dispositions.",
    )
    args = parser.parse_args()

    text = args.report.read_text(encoding="utf-8", errors="replace")
    issues = check_report(text, run_dir=args.run_dir)
    payload = issue_payload(
        "report_gate_check",
        issues,
        {"report": str(args.report), "bytes": len(text.encode("utf-8", errors="replace"))},
    )
    emit_json(payload)
    return 1 if payload["status"] == "failed" else 0


def check_report(text: str, *, run_dir: Path | None = None) -> list[Issue]:
    issues: list[Issue] = []
    findings = _section_any(text, ("Findings", "漏洞", "已确认漏洞"))
    if findings and re.search(r"(^|\n)\s*#{3,}\s*\[?CAND\]?-", findings, re.IGNORECASE):
        issues.append(
            Issue(
                "REPORT010",
                "Candidate signal appears inside Findings; keep candidates outside confirmed findings.",
            )
        )
    confirmed_findings = _section_any(text, ("已确认漏洞", "Confirmed Findings")) or findings
    if confirmed_findings:
        issues.extend(_check_confirmed_findings(confirmed_findings))
    if findings and re.search(r"\b(tool_output|schema_gap|raw_observation)\b", findings, re.IGNORECASE):
        issues.append(
            Issue(
                "REPORT011",
                "Pre-promotion evidence observation appears inside Findings without routing context.",
                severity="warning",
            )
        )
    complete_claim = re.search(r"\b(status|coverage)\s*:\s*complete\b", text, re.IGNORECASE) or re.search(
        r"\bcomplete coverage\b", text, re.IGNORECASE
    ) or re.search(r"(状态|覆盖状态)\s*[:：]\s*(完整|已完成|全部覆盖)", text) or re.search(r"完整覆盖|全部覆盖", text)
    open_schema_gap = re.search(r"\bschema_gap\s*:\s*(open|unrouted|pending)\b", text, re.IGNORECASE)
    open_observation = re.search(r"\b(unrouted|open)\s+(evidence observation|schema gap)", text, re.IGNORECASE) or re.search(
        r"(未路由|开放).*(证据观察|Schema 缺口)", text
    )
    if complete_claim and (open_schema_gap or open_observation):
        issues.append(
            Issue(
                "REPORT020",
                "Report claims complete coverage while schema gaps or evidence observations remain open.",
            )
        )
    if run_dir is not None:
        issues.extend(_check_dangerous_capability_routing(text, run_dir, bool(complete_claim)))
    return issues


def _check_dangerous_capability_routing(text: str, run_dir: Path, complete_claim: bool) -> list[Issue]:
    issues: list[Issue] = []
    ledger_path = run_dir / "dangerous-capabilities.jsonl"
    if not ledger_path.exists():
        issues.append(Issue("REPORT040", "dangerous-capabilities.jsonl is missing", file=str(ledger_path)))
        return issues
    for row in read_jsonl(ledger_path):
        rid = str(row.get("id") or "<missing>")
        if "_parse_error" in row:
            issues.append(Issue("REPORT041", row["_parse_error"], file=str(ledger_path), line=row.get("_line")))
            continue
        disposition = row.get("disposition")
        if disposition == "unreviewed":
            issues.append(Issue("REPORT042", "dangerous capability remains unreviewed", record_id=rid))
            continue
        if disposition in {"confirmed_finding", "high_risk_alert", "candidate", "coverage_debt"}:
            refs = row.get("report_refs")
            if not isinstance(refs, list) or not refs:
                issues.append(Issue("REPORT043", f"{disposition} has no report_refs", record_id=rid))
                continue
            destination = _dangerous_capability_destination(text, disposition)
            destination_folded = destination.casefold()
            if not any(isinstance(ref, str) and ref.strip().casefold() in destination_folded for ref in refs):
                issues.append(Issue("REPORT044", f"required report section does not contain a stable report_ref for {disposition}", record_id=rid))
    if complete_claim and any(issue.code in {"REPORT040", "REPORT041", "REPORT042", "REPORT043", "REPORT044"} for issue in issues):
        issues.append(Issue("REPORT045", "report claims complete coverage while dangerous capability routing is incomplete"))
    return issues


def _dangerous_capability_destination(text: str, disposition: str) -> str:
    headings = {
        "confirmed_finding": ("已确认漏洞", "Confirmed Findings", "Findings", "漏洞"),
        "high_risk_alert": (
            "高风险危险能力告警",
            "High-Risk Dangerous Capability Alerts",
            "High-Risk Sink Alerts",
        ),
        "candidate": ("候选信号", "Candidate Signals"),
        "coverage_debt": ("覆盖债务", "Coverage Debt"),
    }
    return _section_any(text, headings.get(disposition, ()))


def _check_confirmed_findings(section: str) -> list[Issue]:
    issues: list[Issue] = []
    parsed = parse_markdown_findings(section)
    if not parsed:
        return issues

    expected_by_severity: dict[str, int] = {}
    for finding in parsed:
        missing = []
        for field_key, field_name in MARKDOWN_REQUIRED_FIELDS.items():
            value = _field_value(finding.fields, field_key)
            if value is None or not value.strip():
                missing.append(field_name)
        if missing:
            issues.append(
                Issue(
                    "REPORT030",
                    "Confirmed finding is missing canonical fields: " + ", ".join(missing),
                    line=finding.start_line,
                )
            )
        fingerprint = (_field_value(finding.fields, "fingerprint") or "").strip()
        if not fingerprint:
            issues.append(
                Issue(
                    "REPORT031",
                    "Confirmed finding is missing a stable Fingerprint field.",
                    line=finding.start_line,
                )
            )
        severity_key = finding.severity.casefold()
        expected_by_severity[severity_key] = expected_by_severity.get(severity_key, 0) + 1
        expected = expected_by_severity[severity_key]
        if finding.number != expected:
            issues.append(
                Issue(
                    "REPORT032",
                    (
                        "Confirmed finding display IDs must be stable and sequential within each "
                        f"severity; expected [{finding.severity.upper()}]-{expected:03d}."
                    ),
                    line=finding.start_line,
                )
            )
    return issues


def _field_value(fields: dict[str, str], field_key: str) -> str | None:
    for name in MARKDOWN_FIELD_ALIASES.get(field_key, (MARKDOWN_REQUIRED_FIELDS[field_key],)):
        value = fields.get(name.casefold())
        if value is not None:
            return value
    return None


def _section_any(text: str, headings: tuple[str, ...]) -> str:
    for heading in headings:
        section = _section(text, heading)
        if section:
            return section
    return ""


def _section(text: str, heading: str) -> str:
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.IGNORECASE | re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return ""
    next_heading = re.search(r"^##\s+", text[match.end() :], re.MULTILINE)
    if not next_heading:
        return text[match.end() :]
    return text[match.end() : match.end() + next_heading.start()]


if __name__ == "__main__":
    raise SystemExit(main())
