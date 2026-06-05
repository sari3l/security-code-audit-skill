from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
    ".security-code-audit-state",
    ".security-code-audit-reports",
}

TEXT_EXTENSIONS = {
    ".bash",
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".js",
    ".jsx",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

DEFAULT_MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    severity: str = "error"
    file: str | None = None
    line: int | None = None
    record_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def emit_json(payload: dict[str, Any]) -> None:
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                records.append(
                    {
                        "_parse_error": str(exc),
                        "_line": lineno,
                        "id": f"parse-error-{lineno}",
                    }
                )
                continue
            if isinstance(value, dict):
                records.append(value)
            else:
                records.append(
                    {
                        "_parse_error": "JSONL row is not an object",
                        "_line": lineno,
                        "id": f"parse-error-{lineno}",
                    }
                )
    return records


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def iter_text_files(root: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Iterable[Path]:
    root = root.resolve()
    if root.is_file():
        if _is_candidate_text_file(root, max_bytes=max_bytes):
            yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".cache")]
        current_path = Path(current)
        for name in sorted(files):
            path = current_path / name
            if _is_candidate_text_file(path, max_bytes=max_bytes):
                yield path


def _is_candidate_text_file(path: Path, *, max_bytes: int) -> bool:
    if path.name in {".DS_Store"}:
        return False
    if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {
        "Dockerfile",
        "Makefile",
        "AGENTS.md",
        "SKILL.md",
    }:
        return False
    try:
        stat = path.stat()
    except OSError:
        return False
    if stat.st_size > max_bytes:
        return False
    try:
        sample = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in sample


def stable_id(prefix: str, *parts: Any) -> str:
    text = "|".join(str(part) for part in parts)
    value = 2166136261
    for byte in text.encode("utf-8", errors="replace"):
        value ^= byte
        value = (value * 16777619) & 0xFFFFFFFF
    return f"{prefix}-{value:08x}"


def line_excerpt(line: str, *, limit: int = 300) -> str:
    compact = re.sub(r"\s+", " ", line).strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3].rstrip() + "..."


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected integer, got {value!r}") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be >= 1")
    return parsed


def status_from_issues(issues: list[Issue]) -> str:
    return "failed" if any(issue.severity == "error" for issue in issues) else "ok"


def issue_payload(tool: str, issues: list[Issue], summary: dict[str, Any]) -> dict[str, Any]:
    status = status_from_issues(issues)
    return {
        "tool": tool,
        "status": status,
        "issues": [issue.to_dict() for issue in issues],
        "summary": summary,
        "open_world_notice": (
            "Tool output is advisory. Absence of normalized records never proves safety; "
            "unmapped or raw observations remain valid audit signals."
        ),
    }
