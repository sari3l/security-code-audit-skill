#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from security_audit_tools.common import Issue, emit_json, issue_payload
from security_audit_tools.reporting import MARKDOWN_REQUIRED_FIELDS, parse_markdown_findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Check report maturity and routing gates.")
    parser.add_argument("report", type=Path)
    args = parser.parse_args()

    text = args.report.read_text(encoding="utf-8", errors="replace")
    issues = check_report(text)
    payload = issue_payload(
        "report_gate_check",
        issues,
        {"report": str(args.report), "bytes": len(text.encode("utf-8", errors="replace"))},
    )
    emit_json(payload)
    return 1 if payload["status"] == "failed" else 0


def check_report(text: str) -> list[Issue]:
    issues: list[Issue] = []
    findings = _section(text, "Findings")
    if findings and re.search(r"(^|\n)\s*#{3,}\s*\[?CAND\]?-", findings, re.IGNORECASE):
        issues.append(
            Issue(
                "REPORT010",
                "Candidate signal appears inside Findings; keep candidates outside confirmed findings.",
            )
        )
    confirmed_findings = _section(text, "Confirmed Findings") or findings
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
    )
    open_schema_gap = re.search(r"\bschema_gap\s*:\s*(open|unrouted|pending)\b", text, re.IGNORECASE)
    open_observation = re.search(r"\b(unrouted|open)\s+(evidence observation|schema gap)", text, re.IGNORECASE)
    if complete_claim and (open_schema_gap or open_observation):
        issues.append(
            Issue(
                "REPORT020",
                "Report claims complete coverage while schema gaps or evidence observations remain open.",
            )
        )
    return issues


def _check_confirmed_findings(section: str) -> list[Issue]:
    issues: list[Issue] = []
    parsed = parse_markdown_findings(section)
    if not parsed:
        return issues

    expected_by_severity: dict[str, int] = {}
    for finding in parsed:
        missing = []
        for field_name in MARKDOWN_REQUIRED_FIELDS.values():
            value = finding.fields.get(field_name.casefold())
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
        fingerprint = finding.fields.get("fingerprint", "").strip()
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
