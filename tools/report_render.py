#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from security_audit_tools.common import Issue, emit_json, issue_payload, read_jsonl
from security_audit_tools.reporting import assign_display_ids, missing_schema_fields


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render canonical finding.v1 JSONL records into stable Markdown findings."
    )
    parser.add_argument("findings", type=Path, help="Path to findings.jsonl")
    parser.add_argument("--out", type=Path, required=True, help="Markdown output path")
    parser.add_argument(
        "--section-only",
        action="store_true",
        help="Render only finding entries without the surrounding Confirmed Findings heading.",
    )
    parser.add_argument(
        "--title",
        default="Security Audit Report",
        help="Report title used when rendering a full Markdown report.",
    )
    parser.add_argument(
        "--coverage",
        help="Optional report-level coverage status, for example Partial or Complete.",
    )
    args = parser.parse_args()

    records = read_jsonl(args.findings)
    issues = validate_findings(records)
    if any(issue.severity == "error" for issue in issues):
        payload = issue_payload(
            "report_render",
            issues,
            {"findings": str(args.findings), "records": len(records), "out": str(args.out)},
        )
        emit_json(payload)
        return 1

    rendered = render_findings(
        records,
        section_only=args.section_only,
        title=args.title,
        coverage=args.coverage,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered, encoding="utf-8")
    payload = issue_payload(
        "report_render",
        issues,
        {"findings": str(args.findings), "records": len(records), "out": str(args.out)},
    )
    emit_json(payload)
    return 0


def validate_findings(records: list[dict[str, Any]]) -> list[Issue]:
    issues: list[Issue] = []
    seen: set[str] = set()
    for index, record in enumerate(records, 1):
        if "_parse_error" in record:
            issues.append(
                Issue(
                    "RENDER001",
                    f"findings.jsonl row {index} is not valid JSON: {record['_parse_error']}",
                    record_id=str(record.get("id", index)),
                )
            )
            continue
        missing = missing_schema_fields(record)
        if missing:
            issues.append(
                Issue(
                    "RENDER010",
                    "canonical finding is missing required fields: " + ", ".join(missing),
                    record_id=str(record.get("fingerprint", index)),
                )
            )
        fingerprint = str(record.get("fingerprint", "")).strip()
        if fingerprint and fingerprint in seen:
            issues.append(
                Issue(
                    "RENDER020",
                    f"duplicate finding fingerprint: {fingerprint}",
                    record_id=fingerprint,
                )
            )
        seen.add(fingerprint)
    return issues


def render_findings(
    records: list[dict[str, Any]],
    *,
    section_only: bool = False,
    title: str = "Security Audit Report",
    coverage: str | None = None,
) -> str:
    lines: list[str] = []
    if section_only:
        pass
    else:
        lines.append(f"# {title}")
        lines.append("")
        if coverage:
            lines.append(f"Coverage: {coverage}")
            lines.append("")
        lines.extend(["## Confirmed Findings", ""])
    if not records:
        lines.append("None.")
        lines.append("")
        return "\n".join(lines)

    for display_id, finding in assign_display_ids(records):
        lines.extend(_render_finding(display_id, finding))
        lines.append("")
    return "\n".join(lines)


def _render_finding(display_id: str, finding: dict[str, Any]) -> list[str]:
    related = _join_list(finding.get("related_findings"), default="None.")
    refs = _join_list(finding.get("evidence_refs"), default="None.")
    return [
        f"### {display_id}: {finding['title']}",
        f"- **Severity**: {finding['severity']}",
        f"- **Maturity**: {finding['maturity']}",
        f"- **Category / Surface**: {finding['category_surface']}",
        f"- **Fingerprint**: {finding['fingerprint']}",
        f"- **Location**: {_join_list(finding['locations'])}",
        f"- **Status**: {finding['status']}",
        f"- **Evidence Observation Refs**: {refs}",
        f"- **Description**: {finding['description']}",
        f"- **Attack Vector**: {finding['attack_vector']}",
        f"- **Impact**: {finding['impact']}",
        f"- **PoC**: {finding['poc']}",
        f"- **Evidence**: {finding['evidence']}",
        f"- **Minimal Fix**: {finding['minimal_fix']}",
        f"- **Hardening**: {finding['hardening']}",
        f"- **Related Findings**: {related}",
    ]


def _join_list(value: Any, *, default: str = "") -> str:
    if isinstance(value, list):
        if not value:
            return default
        return ", ".join(str(item) for item in value)
    if value is None:
        return default
    return str(value)


if __name__ == "__main__":
    raise SystemExit(main())
