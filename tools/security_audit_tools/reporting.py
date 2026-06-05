from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


SCHEMA_VERSION = "finding.v1"

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

REQUIRED_FINDING_FIELDS = (
    "schema_version",
    "fingerprint",
    "severity",
    "maturity",
    "category_surface",
    "locations",
    "status",
    "title",
    "description",
    "attack_vector",
    "impact",
    "poc",
    "evidence",
    "minimal_fix",
    "hardening",
    "related_findings",
    "evidence_refs",
)

NONEMPTY_FINDING_FIELDS = set(REQUIRED_FINDING_FIELDS) - {"related_findings"}

MARKDOWN_REQUIRED_FIELDS = {
    "severity": "Severity",
    "maturity": "Maturity",
    "category_surface": "Category / Surface",
    "fingerprint": "Fingerprint",
    "locations": "Location",
    "status": "Status",
    "description": "Description",
    "attack_vector": "Attack Vector",
    "impact": "Impact",
    "poc": "PoC",
    "evidence": "Evidence",
    "minimal_fix": "Minimal Fix",
    "hardening": "Hardening",
    "related_findings": "Related Findings",
    "evidence_refs": "Evidence Observation Refs",
}


@dataclass(frozen=True)
class MarkdownFinding:
    severity: str
    number: int
    title: str
    fields: dict[str, str]
    start_line: int


def normalize_severity(value: Any) -> str:
    return str(value or "").strip().lower()


def severity_label(value: Any) -> str:
    normalized = normalize_severity(value)
    if normalized == "info":
        return "INFO"
    return normalized.upper()


def finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    severity = normalize_severity(finding.get("severity"))
    return (
        SEVERITY_ORDER.get(severity, 99),
        str(finding.get("category_surface", "")).casefold(),
        str(finding.get("fingerprint", "")).casefold(),
    )


def sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=finding_sort_key)


def assign_display_ids(findings: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    counts: dict[str, int] = {}
    assigned: list[tuple[str, dict[str, Any]]] = []
    for finding in sorted_findings(findings):
        label = severity_label(finding.get("severity"))
        counts[label] = counts.get(label, 0) + 1
        assigned.append((f"[{label}]-{counts[label]:03d}", finding))
    return assigned


def missing_schema_fields(finding: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    for field in REQUIRED_FINDING_FIELDS:
        if field not in finding:
            missing.append(field)
            continue
        value = finding.get(field)
        if value is None:
            missing.append(field)
        elif isinstance(value, str) and not value.strip():
            missing.append(field)
        elif field in NONEMPTY_FINDING_FIELDS and isinstance(value, list) and not value:
            missing.append(field)
    if finding.get("schema_version") != SCHEMA_VERSION:
        missing.append("schema_version=finding.v1")
    return missing


def parse_markdown_findings(section: str) -> list[MarkdownFinding]:
    heading_pattern = re.compile(
        r"^(?P<heading>#{3,})\s+\[(?P<severity>[A-Za-z]+)\]-(?P<number>\d{3}):\s*(?P<title>.+?)\s*$",
        re.MULTILINE,
    )
    matches = list(heading_pattern.finditer(section))
    findings: list[MarkdownFinding] = []
    for index, match in enumerate(matches):
        body_start = match.end()
        body_end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        body = section[body_start:body_end]
        fields = _parse_markdown_fields(body)
        start_line = section[: match.start()].count("\n") + 1
        findings.append(
            MarkdownFinding(
                severity=match.group("severity"),
                number=int(match.group("number")),
                title=match.group("title").strip(),
                fields=fields,
                start_line=start_line,
            )
        )
    return findings


def _parse_markdown_fields(body: str) -> dict[str, str]:
    field_pattern = re.compile(r"^-\s+\*\*(?P<name>[^*]+)\*\*:\s*(?P<value>.*)$", re.MULTILINE)
    matches = list(field_pattern.finditer(body))
    fields: dict[str, str] = {}
    for index, match in enumerate(matches):
        value_start = match.start("value")
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        raw_value = body[value_start:value_end].strip()
        fields[match.group("name").strip().casefold()] = raw_value
    return fields
