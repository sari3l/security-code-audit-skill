#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from security_audit_tools.common import emit_json, iter_text_files, write_jsonl


DYNAMIC_NAMES = {"eval", "exec", "compile"}
SENTINEL_FAMILIES = {
    "dynamic_code_evaluation",
    "shell_command_execution",
    "shell_code_loading",
    "signing_material",
    "signed_state_consumer",
}
SESSION_READ_METHODS = {"get", "items", "keys", "values", "__contains__"}
SESSION_WRITE_METHODS = {"clear", "pop", "popitem", "setdefault", "update"}
SHELL_SUFFIXES = {".bash", ".ksh", ".sh", ".zsh"}
SHELL_CONTAINER_SUFFIXES = {".service", ".yaml", ".yml"}
SHELL_FILE_NAMES = {"Dockerfile", "Makefile", "Procfile"}
SOURCE_RE = re.compile(
    r"(?:^\s*|\bRUN\s+|[;&|]\s*)(?:source\s+|\.\s+)",
    re.IGNORECASE,
)
SHELL_EVAL_RE = re.compile(r"(?:^\s*|[;&|]\s*)eval(?:\s+|$)")
SHELL_COMMAND_RE = re.compile(r"\b(?:ba|z|k)?sh\s+-c(?:\s+|$)")
JS_EVAL_RE = re.compile(r"(?<![\w.])eval\s*\(")
JS_FUNCTION_RE = re.compile(r"(?<![\w.])Function\s*\(")
JS_STRING_TIMER_RE = re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]")
JS_COMMAND_RE = re.compile(r"\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|fork)\s*\(")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed an open-world census of dangerous execution and signing capabilities."
    )
    parser.add_argument("root", type=Path, help="Repository or source tree to inspect.")
    parser.add_argument("--jsonl", type=Path, help="Optional path for raw census records.")
    args = parser.parse_args()

    payload = seed_tree(args.root)
    records = payload["records"]
    if args.jsonl and payload["status"] == "ok":
        write_jsonl(args.jsonl, records)
    emit_json(payload)
    return 0 if payload["status"] == "ok" else 1


def scan_tree(root: Path) -> list[dict[str, Any]]:
    payload = seed_tree(root)
    if payload["status"] != "ok":
        raise ValueError(payload["issues"][0]["message"])
    return payload["records"]


def seed_tree(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.exists():
        return _failed_payload(root, "SEED001", "target root does not exist")
    paths = list(iter_text_files(root))
    if not paths:
        return _failed_payload(root, "SEED002", "target contains no supported auditable text files")

    records: list[dict[str, Any]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = _relative_path(path, root)
        if path.suffix.lower() == ".py":
            records.extend(_scan_python(text, relative))
        if path.suffix.lower() in {".js", ".jsx", ".mjs", ".ts", ".tsx"}:
            records.extend(_scan_javascript(text, relative))
        if _is_shell_container(path, text):
            records.extend(_scan_shell(text, relative))
    records.sort(key=lambda row: (row["path"], row["line"], row["family"], row["kind"]))
    records = _deduplicate(records)
    family_totals: dict[str, int] = {family: 0 for family in SENTINEL_FAMILIES}
    for record in records:
        family = record["family"]
        family_totals[family] = family_totals.get(family, 0) + 1
    return {
        "tool": "dangerous_capability_seed",
        "status": "ok",
        "root": str(root),
        "files_considered": len(paths),
        "discovered_total": len(records),
        "family_totals": dict(sorted(family_totals.items())),
        "records": records,
        "issues": [],
        "notice": (
            "Open-world seed only. Empty findings are not proof of safety; inspect aliases, "
            "wrappers, generated code, framework registration, and deployment semantics manually."
        ),
    }


def _failed_payload(root: Path, code: str, message: str) -> dict[str, Any]:
    return {
        "tool": "dangerous_capability_seed",
        "status": "failed",
        "root": str(root),
        "files_considered": 0,
        "discovered_total": 0,
        "family_totals": {},
        "records": [],
        "issues": [{"code": code, "message": message}],
        "notice": "No census claim can be made for this target.",
    }


def _scan_python(text: str, path: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _scan_python_fallback(text, path)

    lines = text.splitlines()
    records: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dynamic_kind = _python_dynamic_call_kind(node)
            if dynamic_kind:
                records.append(
                    _record(
                        "dynamic_code_evaluation",
                        dynamic_kind,
                        path,
                        node.lineno,
                        _line(lines, node.lineno),
                    )
                )
            command_kind = _python_command_call_kind(node)
            if command_kind:
                records.append(
                    _record(
                        "shell_command_execution",
                        command_kind,
                        path,
                        node.lineno,
                        _line(lines, node.lineno),
                    )
                )
            session_kind = _session_call_kind(node)
            if session_kind:
                records.append(
                    _record(
                        "signed_state_consumer",
                        session_kind,
                        path,
                        node.lineno,
                        _line(lines, node.lineno),
                    )
                )
            for keyword in node.keywords:
                if keyword.arg and _is_signing_key_name(keyword.arg) and _has_hardcoded_material(keyword.value):
                    records.append(
                        _record(
                            "signing_material",
                            "hardcoded_signing_key",
                            path,
                            node.lineno,
                            "<redacted hardcoded signing material>",
                        )
                    )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = _assignment_targets(node)
            if value is not None and any(_is_signing_key_target(target) for target in targets):
                if _has_hardcoded_material(value):
                    kind = "hardcoded_signing_key_fallback" if _is_literal_fallback(value) else "hardcoded_signing_key"
                    records.append(
                        _record(
                            "signing_material",
                            kind,
                            path,
                            node.lineno,
                            "<redacted hardcoded signing material>",
                        )
                    )
        elif isinstance(node, ast.Subscript) and _is_session_name(node.value):
            kind = "session_write" if isinstance(node.ctx, ast.Store) else "session_read"
            records.append(
                _record(
                    "signed_state_consumer",
                    kind,
                    path,
                    node.lineno,
                    _line(lines, node.lineno),
                )
            )
        elif isinstance(node, ast.Compare) and any(_is_session_name(item) for item in node.comparators):
            if any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
                records.append(
                    _record(
                        "signed_state_consumer",
                        "session_membership_test",
                        path,
                        node.lineno,
                        _line(lines, node.lineno),
                    )
                )
    return records


def _python_dynamic_call_kind(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        if func.id in DYNAMIC_NAMES:
            return f"python_{func.id}"
        if func.id == "__import__":
            return "python_dynamic_import"
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and func.value.id in {"builtins", "__builtins__"}:
            if func.attr in DYNAMIC_NAMES:
                return f"python_{func.attr}"
        if isinstance(func.value, ast.Name) and func.value.id == "importlib" and func.attr == "import_module":
            return "python_dynamic_import"
    if isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "getattr":
        if len(func.args) >= 2 and isinstance(func.args[1], ast.Constant):
            name = func.args[1].value
            if name in DYNAMIC_NAMES:
                return f"python_reflective_{name}"
    return None


def _python_command_call_kind(node: ast.Call) -> str | None:
    func = node.func
    if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
        return None
    if func.value.id == "os" and func.attr in {"system", "popen"}:
        return f"python_os_{func.attr}"
    if func.value.id == "subprocess" and func.attr in {
        "run",
        "call",
        "Popen",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    }:
        return f"python_subprocess_{func.attr.lower()}"
    return None


def _session_call_kind(node: ast.Call) -> str | None:
    func = node.func
    if not isinstance(func, ast.Attribute) or not _is_session_name(func.value):
        return None
    if func.attr in SESSION_READ_METHODS:
        return "session_read"
    if func.attr in SESSION_WRITE_METHODS:
        return "session_write"
    return None


def _assignment_targets(node: ast.Assign | ast.AnnAssign | ast.NamedExpr) -> Iterable[ast.AST]:
    if isinstance(node, ast.Assign):
        return node.targets
    return (node.target,)


def _is_signing_key_target(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return _is_signing_key_name(node.id)
    if isinstance(node, ast.Attribute):
        return _is_signing_key_name(node.attr)
    if isinstance(node, ast.Subscript):
        key = _constant_subscript_key(node.slice)
        return isinstance(key, str) and _is_signing_key_name(key)
    return False


def _is_signing_key_name(name: str) -> bool:
    normalized = name.upper()
    return normalized in {"SECRET_KEY", "SESSION_SECRET", "JWT_SECRET", "HMAC_KEY"} or normalized.endswith(
        ("_SIGNING_KEY", "_SIGNING_SECRET")
    )


def _constant_subscript_key(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    return None


def _has_hardcoded_material(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes)) and bool(node.value)
    if isinstance(node, ast.BoolOp):
        return any(_has_hardcoded_material(value) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _has_hardcoded_material(node.left) or _has_hardcoded_material(node.right)
    return False


def _is_literal_fallback(node: ast.AST) -> bool:
    return isinstance(node, ast.BoolOp) and any(_has_hardcoded_material(value) for value in node.values)


def _is_session_name(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "session"


def _scan_python_fallback(text: str, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    pattern = re.compile(r"(?<![\w.])(?P<kind>eval|exec|compile)\s*\(")
    for lineno, line in enumerate(text.splitlines(), 1):
        for match in pattern.finditer(line):
            records.append(
                _record(
                    "dynamic_code_evaluation",
                    f"python_{match.group('kind')}",
                    path,
                    lineno,
                    line,
                )
            )
    return records


def _scan_javascript(text: str, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    patterns = (
        (JS_EVAL_RE, "javascript_eval"),
        (JS_FUNCTION_RE, "javascript_function_constructor"),
        (JS_STRING_TIMER_RE, "javascript_string_timer"),
    )
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        for pattern, kind in patterns:
            if pattern.search(line):
                records.append(_record("dynamic_code_evaluation", kind, path, lineno, line))
        if JS_COMMAND_RE.search(line):
            records.append(_record("shell_command_execution", "javascript_command", path, lineno, line))
    return records


def _is_shell_container(path: Path, text: str) -> bool:
    if path.suffix.lower() in SHELL_SUFFIXES | SHELL_CONTAINER_SUFFIXES:
        return True
    if path.name in SHELL_FILE_NAMES or path.name.startswith(("Dockerfile.", "Makefile.")):
        return True
    first_line = text.splitlines()[0] if text.splitlines() else ""
    return first_line.startswith("#!") and re.search(r"\b(?:ba|z|k)?sh\b", first_line) is not None


def _scan_shell(text: str, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if SOURCE_RE.search(line):
            records.append(_record("shell_code_loading", "shell_source", path, lineno, line))
        if SHELL_EVAL_RE.search(line):
            records.append(_record("shell_code_loading", "shell_eval", path, lineno, line))
        if SHELL_COMMAND_RE.search(line):
            records.append(_record("shell_code_loading", "shell_command_string", path, lineno, line))
            records.append(_record("shell_command_execution", "shell_command_string", path, lineno, line))
    return records


def _record(family: str, kind: str, path: str, line: int, snippet: str) -> dict[str, Any]:
    clean_snippet = " ".join(snippet.strip().split())[:240]
    identity = f"{family}\0{kind}\0{path}\0{line}".encode("utf-8", errors="replace")
    return {
        "id": "danger-" + hashlib.sha256(identity).hexdigest()[:16],
        "family": family,
        "kind": kind,
        "path": path,
        "line": line,
        "location": f"{path}:{line}",
        "symbol_or_snippet": clean_snippet,
        "source_reachability": "unknown",
        "disposition": "unreviewed",
        "trace_refs": [],
        "finding_refs": [],
        "report_refs": [],
        "negative_evidence": [],
        "coverage_debt_refs": [],
    }


def _relative_path(path: Path, root: Path) -> str:
    if root.is_file() and path.resolve() == root.resolve():
        return path.name
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _line(lines: list[str], lineno: int) -> str:
    if 0 < lineno <= len(lines):
        return lines[lineno - 1]
    return ""


def _deduplicate(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, int]] = set()
    output: list[dict[str, Any]] = []
    for record in records:
        key = (record["family"], record["kind"], record["path"], record["line"])
        if key in seen:
            continue
        seen.add(key)
        output.append(record)
    return output


if __name__ == "__main__":
    raise SystemExit(main())
