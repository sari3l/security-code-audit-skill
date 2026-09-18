#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

from security_audit_tools.common import Issue, emit_json, issue_payload, read_jsonl
from security_audit_tools.reporting import assign_display_ids, missing_schema_fields


REPORT_NAME_RE = re.compile(
    r"^(security-code-audit-\d{4}-\d{2}-\d{2}-\d{6}-[A-Za-z0-9_-]+-[A-Za-z0-9]{6,})\.md$"
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render canonical finding.v1 JSONL records into stable Markdown findings."
    )
    parser.add_argument("findings", type=Path, help="Path to canonical finding.v1 JSONL input")
    parser.add_argument("--out", type=Path, required=True, help="Markdown output path")
    parser.add_argument(
        "--section-only",
        action="store_true",
        help="Render only finding entries without the surrounding Confirmed Findings heading.",
    )
    parser.add_argument(
        "--title",
        default="代码安全审计报告",
        help="Report title used when rendering a full Markdown report.",
    )
    parser.add_argument(
        "--coverage",
        help="Optional report-level coverage status, for example Partial or Complete.",
    )
    args = parser.parse_args()

    records = read_jsonl(args.findings)
    issues = validate_findings(records)
    canonical_findings, output_issue = canonical_findings_path(args.out)
    if output_issue is not None:
        issues.append(output_issue)
    if any(issue.severity == "error" for issue in issues):
        payload = issue_payload(
            "report_render",
            issues,
            {
                "findings": str(args.findings),
                "canonical_findings": str(canonical_findings) if canonical_findings else "",
                "records": len(records),
                "out": str(args.out),
            },
        )
        emit_json(payload)
        return 1

    rendered = render_findings(
        records,
        section_only=args.section_only,
        title=args.title,
        coverage=args.coverage,
    )
    report_issue = validate_report_destination(args.out, rendered)
    if report_issue is not None:
        payload = issue_payload(
            "report_render",
            [report_issue],
            {
                "findings": str(args.findings),
                "canonical_findings": str(canonical_findings),
                "records": len(records),
                "out": str(args.out),
            },
        )
        emit_json(payload)
        return 1

    copy_issue = write_canonical_findings(args.findings, canonical_findings)
    if copy_issue is not None:
        payload = issue_payload(
            "report_render",
            [copy_issue],
            {
                "findings": str(args.findings),
                "canonical_findings": str(canonical_findings),
                "records": len(records),
                "out": str(args.out),
            },
        )
        emit_json(payload)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered, encoding="utf-8")
    payload = issue_payload(
        "report_render",
        issues,
        {
            "findings": str(args.findings),
            "canonical_findings": str(canonical_findings),
            "records": len(records),
            "out": str(args.out),
        },
    )
    emit_json(payload)
    return 0


def canonical_findings_path(report_path: Path) -> tuple[Path | None, Issue | None]:
    match = REPORT_NAME_RE.fullmatch(report_path.name)
    if report_path.parent.name != "output" or not match:
        return None, Issue(
            "RENDER030",
            "report output must be under output/ and named output/security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}.md",
            file=str(report_path),
        )
    return report_path.parent / f"{match.group(1)}-findings.jsonl", None


def write_canonical_findings(source: Path, destination: Path | None) -> Issue | None:
    if destination is None:
        return Issue("RENDER031", "canonical findings path could not be derived", file=str(source))
    source_text = source.read_text(encoding="utf-8")
    if source_text and not source_text.endswith("\n"):
        source_text += "\n"
    if source.resolve(strict=False) == destination.resolve(strict=False):
        return None
    if destination.exists():
        current = destination.read_text(encoding="utf-8")
        if current == source_text:
            return None
        return Issue(
            "RENDER032",
            "canonical findings output already exists with different content; choose a new timestamp/hash stem to avoid overwriting scan artifacts",
            file=str(destination),
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(source_text, encoding="utf-8")
    return None


def validate_report_destination(report_path: Path, rendered: str) -> Issue | None:
    if not report_path.exists():
        return None
    current = report_path.read_text(encoding="utf-8")
    if current == rendered:
        return None
    return Issue(
        "RENDER033",
        "report output already exists with different content; choose a new timestamp/hash stem to avoid overwriting scan artifacts",
        file=str(report_path),
    )


def validate_findings(records: list[dict[str, Any]]) -> list[Issue]:
    issues: list[Issue] = []
    seen: set[str] = set()
    for index, record in enumerate(records, 1):
        if "_parse_error" in record:
            issues.append(
                Issue(
                    "RENDER001",
                    f"canonical findings JSONL row {index} is not valid JSON: {record['_parse_error']}",
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
    title: str = "代码安全审计报告",
    coverage: str | None = None,
) -> str:
    lines: list[str] = []
    if section_only:
        pass
    else:
        lines.append(f"# {title}")
        lines.append("")
        if coverage:
            lines.append(f"覆盖状态: {coverage}")
            lines.append("")
        lines.extend(["## 已确认漏洞", ""])
    if not records:
        lines.append("无。")
        lines.append("")
        return "\n".join(lines)

    for display_id, finding in assign_display_ids(records):
        lines.extend(_render_finding(display_id, finding))
        lines.append("")
    return "\n".join(lines)


def _render_finding(display_id: str, finding: dict[str, Any]) -> list[str]:
    related = _join_list(finding.get("related_findings"), default="无。")
    refs = _join_list(finding.get("evidence_refs"), default="无。")
    lines = [
        f"### {display_id}: {finding['title']}",
        f"- **严重性**: {_zh_severity(finding['severity'])}",
        f"- **成熟度**: {_zh_status_value(finding['maturity'])}",
        f"- **类别 / 审计面**: {finding['category_surface']}",
        f"- **指纹**: {finding['fingerprint']}",
        f"- **位置**: {_join_list(finding['locations'])}",
        f"- **状态**: {_zh_status_value(finding['status'])}",
        f"- **证据观察引用**: {refs}",
        f"- **描述**: {finding['description']}",
        f"- **攻击路径**: {finding['attack_vector']}",
        f"- **影响**: {finding['impact']}",
    ]
    lines.extend(_render_markdown_field("PoC", finding["poc"]))
    if finding.get("evidence_chain"):
        lines.extend(_render_chain_field("证据链", finding["evidence_chain"]))
    lines.extend(_render_markdown_field("证据", finding["evidence"]))
    lines.extend(_render_code_field("攻击流程", _mermaid_for_finding(finding), language="mermaid"))
    lines.extend(_render_markdown_field("最小修复", finding["minimal_fix"]))
    lines.extend(_render_markdown_field("加固建议", finding["hardening"]))
    lines.append(f"- **相关漏洞**: {related}")
    return lines


def _zh_severity(value: Any) -> str:
    labels = {
        "critical": "严重",
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "信息",
    }
    return labels.get(str(value).strip().casefold(), str(value))


def _zh_status_value(value: Any) -> str:
    labels = {
        "confirmed": "已确认",
        "candidate": "候选",
        "new": "新增",
        "recurring": "复现",
        "regression": "回归",
        "fixed": "已修复",
        "partially fixed": "部分修复",
        "still present": "仍存在",
        "unable to verify": "无法验证",
        "pending historical validation": "待历史验证",
    }
    return labels.get(str(value).strip().casefold(), str(value))


def _render_markdown_field(name: str, value: Any) -> list[str]:
    if isinstance(value, dict) and "code" in value:
        return _render_code_field(name, value.get("code", ""), language=str(value.get("language", "")).strip())
    if isinstance(value, list):
        return _render_chain_field(name, value)
    text = str(value)
    if "\n" not in text:
        return [f"- **{name}**: {text}"]
    return [f"- **{name}**:", *(_indent_markdown(text))]


def _render_code_field(name: str, code: Any, *, language: str = "") -> list[str]:
    lang = language.strip()
    fence = f"```{lang}" if lang else "```"
    return [
        f"- **{name}**:",
        fence,
        *str(code).splitlines(),
        "```",
    ]


def _render_chain_field(name: str, value: Any) -> list[str]:
    if not isinstance(value, list):
        return _render_markdown_field(name, value)
    lines = [f"- **{name}**:"]
    for index, item in enumerate(value, 1):
        lines.append(f"  {index}. {item}")
    return lines


def _indent_markdown(text: str) -> list[str]:
    return [f"  {line}" if line else "" for line in text.splitlines()]


def _mermaid_for_finding(finding: dict[str, Any]) -> str:
    override = finding.get("mermaid")
    if override:
        return str(override)
    chain = finding.get("evidence_chain", [])
    if not isinstance(chain, list) or not chain:
        return "flowchart LR\n  MissingEvidenceChain[Missing evidence_chain]"
    lines = ["flowchart LR"]
    if len(chain) == 1:
        lines.append(f"  step1[\"{_escape_mermaid_label(str(chain[0]))}\"]")
        return "\n".join(lines)
    for index in range(1, len(chain)):
        left = _escape_mermaid_label(str(chain[index - 1]))
        right = _escape_mermaid_label(str(chain[index]))
        lines.append(f"  step{index}[\"{left}\"] --> step{index + 1}[\"{right}\"]")
    return "\n".join(lines)


def _escape_mermaid_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


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
