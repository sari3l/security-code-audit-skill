#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from audit_plugin_check import check_plugins
from security_audit_tools.common import Issue, emit_json, issue_payload, read_json, read_jsonl
from security_audit_tools.reporting import SEVERITY_ORDER


PLUGINS_ROOT = Path(__file__).resolve().parents[1] / "plugins"
UNREVIEWED = "待本地核对"
DISPOSITION_LABELS = {
    "confirmed_finding": "已确认漏洞",
    "candidate": "候选信号",
    "coverage_debt": "覆盖债务",
    "not_reachable": "不可达",
    "not_present": "当前代码不存在",
    "false_positive": "误报",
    "accepted_risk": "已接受风险",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render installed plugin results from the current audit state as report sections."
    )
    parser.add_argument("--run-dir", type=Path, required=True, help="Current audit state directory")
    parser.add_argument("--out", type=Path, help="Markdown fragment path; prints to stdout when omitted")
    args = parser.parse_args()

    plugins, issues = check_plugins(PLUGINS_ROOT)
    sections = render_plugin_sections(plugins, args.run_dir, issues)
    text = "\n".join(sections)
    if args.out is not None and not any(issue.severity == "error" for issue in issues):
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    payload = issue_payload(
        "plugin_report_render",
        issues,
        {"run_dir": str(args.run_dir), "sections": len(sections), "out": str(args.out) if args.out else ""},
    )
    if args.out is None:
        print(text)
    else:
        emit_json(payload)
    return 1 if payload["status"] == "failed" else 0


def reportable_plugins(plugins: list[dict[str, Any]], run_dir: Path) -> list[dict[str, Any]]:
    """Enabled plugins whose declared context artifact exists for this run."""
    selected = []
    for plugin in plugins:
        report = plugin.get("report") or {}
        context = report.get("context")
        if plugin.get("enabled") is True and context and (run_dir / context).is_file():
            selected.append(plugin)
    return selected


def render_plugin_sections(plugins: list[dict[str, Any]], run_dir: Path, issues: list[Issue]) -> list[str]:
    sections = []
    for plugin in reportable_plugins(plugins, run_dir):
        sections.append(render_plugin_section(plugin, run_dir, issues))
    return sections


def render_plugin_section(plugin: dict[str, Any], run_dir: Path, issues: list[Issue]) -> str:
    report = plugin["report"]
    lines = [f"## {report['heading']}", ""]
    context = _read_context(run_dir / report["context"], issues)
    for item in report.get("summary", []):
        lines.append(f"- **{item['label']}**: {_cell(context.get(item['field']), context, item)}")
    if report.get("summary"):
        lines.append("")

    if "rows" not in report:
        return "\n".join(lines)
    rows = load_plugin_rows(run_dir, report, issues)
    if not rows:
        lines.extend(["插件本次未返回结果行。结果为空不代表依赖安全，请结合上方状态与覆盖债务阅读。", ""])
        return "\n".join(lines)

    columns = report["columns"]
    lines.append("| " + " | ".join(column["label"] for column in columns) + " |")
    lines.append("|" + "|".join(" --- " for _ in columns) + "|")
    for row in rows:
        lines.append("| " + " | ".join(_cell(row.get(column["field"]), row, column) for column in columns) + " |")
    lines.append("")
    reviewed = sum(1 for row in rows if row.get("disposition") not in (None, UNREVIEWED))
    lines.append(f"共 {len(rows)} 条，已本地核对 {reviewed} 条，待核对 {len(rows) - reviewed} 条。")
    lines.append("")
    return "\n".join(lines)


def load_plugin_rows(run_dir: Path, report: dict[str, Any], issues: list[Issue]) -> list[dict[str, Any]]:
    """Merge plugin rows with local review decisions keyed by report.rowKey."""
    key = report["rowKey"]
    rows_path = run_dir / report["rows"]
    rows = [row for row in read_jsonl(rows_path) if _usable(row, rows_path, key, issues)]
    reviews: dict[str, dict[str, Any]] = {}
    if report.get("review"):
        review_path = run_dir / report["review"]
        for review in read_jsonl(review_path):
            if _usable(review, review_path, key, issues):
                reviews[str(review[key])] = review
    known = {str(row[key]) for row in rows}
    for review_key in sorted(set(reviews) - known):
        issues.append(Issue("PLUGINREPORT003", f"review row has no matching plugin result: {review_key}", file=str(run_dir / report["review"])))

    merged = []
    for row in rows:
        combined = {**row, **{name: value for name, value in reviews.get(str(row[key]), {}).items() if value not in (None, "")}}
        combined["disposition"] = DISPOSITION_LABELS.get(str(combined.get("disposition")), combined.get("disposition") or UNREVIEWED)
        merged.append(combined)
    merged.sort(key=lambda row: (SEVERITY_ORDER.get(str(row.get("scanner_severity", row.get("severity", ""))).casefold(), 9), str(row[key])))
    return merged


def _usable(row: dict[str, Any], path: Path, key: str, issues: list[Issue]) -> bool:
    if "_parse_error" in row:
        issues.append(Issue("PLUGINREPORT001", row["_parse_error"], file=str(path), line=row.get("_line")))
        return False
    if row.get(key) in (None, ""):
        issues.append(Issue("PLUGINREPORT002", f"row lacks report key field {key}", file=str(path)))
        return False
    return True


def _read_context(path: Path, issues: list[Issue]) -> dict[str, Any]:
    try:
        value = read_json(path)
    except Exception as exc:  # noqa: BLE001 - stable renderer diagnostics
        issues.append(Issue("PLUGINREPORT004", f"plugin context is invalid JSON: {exc}", file=str(path)))
        return {}
    if not isinstance(value, dict):
        issues.append(Issue("PLUGINREPORT004", "plugin context must contain an object", file=str(path)))
        return {}
    return value


def _cell(value: Any, row: dict[str, Any], column: dict[str, Any]) -> str:
    if isinstance(value, list):
        text = ", ".join(str(item) for item in value) if value else "-"
    elif value in (None, ""):
        text = "-"
    else:
        text = str(value)
    text = _escape(text)
    link = row.get(column.get("link", ""))
    if text != "-" and isinstance(link, str) and link.startswith("https://") and not any(ch in link for ch in " ()<>|\n"):
        return f"[{text}]({link})"
    return text


def _escape(text: str) -> str:
    # Plugin output is remote, untrusted data: keep it inert inside one table cell.
    text = " ".join(text.split())
    for char in ("\\", "|", "`", "*", "_", "[", "]", "<", ">"):
        text = text.replace(char, "\\" + char)
    return text[:300]


if __name__ == "__main__":
    raise SystemExit(main())
