#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from security_audit_tools.common import SKIP_DIRS, emit_json, read_jsonl, write_jsonl


SCANNER_VERSION = "2.0"
MAX_CAPABILITY_FILE_BYTES = 10_000_000
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
POWERSHELL_SUFFIXES = {".ps1"}
SHELL_CONTAINER_SUFFIXES = {".service", ".yaml", ".yml"}
SHELL_FILE_NAMES = {"Dockerfile", "Makefile", "Procfile"}
JAVASCRIPT_SUFFIXES = {".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"}
GENERIC_CODE_SUFFIXES = {".c", ".cc", ".cpp", ".cs", ".go", ".java", ".kt", ".kts", ".php", ".rb", ".rs", ".scala", ".swift"}
SUBPROCESS_CALLS = {"call", "check_call", "check_output", "Popen", "run"}
SOURCE_RE = re.compile(
    r"(?:^\s*|\bRUN\s+|\brun\s*:\s*['\"]?|[;&|]\s*)(?:source\s+|\.\s+)",
    re.IGNORECASE,
)
SHELL_EVAL_RE = re.compile(r"(?:^\s*|\brun\s*:\s*['\"]?|[;&|]\s*)eval(?:\s+|$)", re.IGNORECASE)
SHELL_COMMAND_RE = re.compile(r"\b(?:ba|z|k)?sh\s+-c(?:\s+|$)")
JS_EVAL_RE = re.compile(r"(?<![\w.])eval\s*\(")
JS_FUNCTION_RE = re.compile(r"(?<![\w.])Function\s*\(")
JS_STRING_TIMER_RE = re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]")
JS_COMMAND_RE = re.compile(r"\b(?:child_process\s*\.\s*)?(?:exec|execSync)\s*\(")
GENERIC_DYNAMIC_RE = re.compile(
    r"\b(?:eval|instance_eval|class_eval|module_eval|ScriptEngine\s*\.\s*eval|CSharpScript\s*\.\s*EvaluateAsync?)\s*\(",
    re.IGNORECASE,
)
GENERIC_COMMAND_RE = re.compile(
    r"(?:\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\(|\bProcess\s*\.\s*Start\s*\(|\b(?:system|popen|shell_exec|passthru|proc_open)\s*\(|\bexec\.Command\s*\()",
    re.IGNORECASE,
)
POWERSHELL_EVAL_RE = re.compile(r"(?:\bInvoke-Expression\b|(?:^|[;|]\s*)iex\s+)", re.IGNORECASE)
POWERSHELL_COMMAND_RE = re.compile(r"\b(?:Start-Process|cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-(?:Command|EncodedCommand))\b", re.IGNORECASE)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed an open-world census of dangerous execution and signing capabilities."
    )
    parser.add_argument("root", type=Path, help="Repository or source tree to inspect.")
    parser.add_argument("--jsonl", type=Path, help="Optional path for raw census records.")
    parser.add_argument(
        "--state-dir",
        type=Path,
        help="Write source-bound seed and census artifacts into an audit-state directory.",
    )
    args = parser.parse_args()

    payload = seed_tree(args.root)
    records = payload["records"]
    if args.jsonl and payload["records"]:
        write_jsonl(args.jsonl, records)
    if args.state_dir and payload["files_considered"] > 0:
        write_seed_state(args.state_dir, payload)
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
    paths, discovery_issues = _discover_capability_paths(root)
    if not paths:
        payload = _failed_payload(root, "SEED002", "target contains no supported auditable source files")
        if discovery_issues:
            payload["issues"] = discovery_issues
            payload["files_considered"] = len(discovery_issues)
        return payload

    records: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = list(discovery_issues)
    file_fingerprints: list[tuple[str, str]] = []
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            issues.append({"code": "SEED003", "file": str(path), "message": f"cannot read source file: {exc}"})
            continue
        text = raw.decode("utf-8", errors="replace")
        relative = _relative_path(path, root)
        file_fingerprints.append((relative, hashlib.sha256(raw).hexdigest()))
        if path.suffix.lower() == ".py":
            python_records, parse_issue = _scan_python_with_status(text, relative)
            records.extend(python_records)
            if parse_issue:
                issues.append(parse_issue)
        if path.suffix.lower() in JAVASCRIPT_SUFFIXES:
            records.extend(_scan_javascript(text, relative))
        if path.suffix.lower() in GENERIC_CODE_SUFFIXES:
            records.extend(_scan_generic_code(text, relative))
        if _is_shell_container(path, text):
            records.extend(_scan_shell(text, relative))
    records.sort(key=lambda row: (row["path"], row["line"], row["family"], row["kind"]))
    records = _deduplicate(records)
    family_totals: dict[str, int] = {family: 0 for family in SENTINEL_FAMILIES}
    for record in records:
        family = record["family"]
        family_totals[family] = family_totals.get(family, 0) + 1
    snapshot_digest = _snapshot_digest(file_fingerprints)
    return {
        "tool": "dangerous_capability_seed",
        "scanner_version": SCANNER_VERSION,
        "status": "failed" if issues else "ok",
        "root": str(root),
        "files_considered": len(paths),
        "files_scanned": len(file_fingerprints),
        "snapshot_digest": snapshot_digest,
        "discovered_total": len(records),
        "family_totals": dict(sorted(family_totals.items())),
        "records": records,
        "records_digest": records_digest(records),
        "issues": issues,
        "notice": (
            "Open-world seed only. Empty findings are not proof of safety; inspect aliases, "
            "wrappers, generated code, framework registration, and deployment semantics manually."
        ),
    }


def _is_capability_candidate_path(path: Path, sample: bytes = b"") -> bool:
    suffix = path.suffix.lower()
    if suffix in {".py"} | JAVASCRIPT_SUFFIXES | GENERIC_CODE_SUFFIXES | SHELL_SUFFIXES | POWERSHELL_SUFFIXES | SHELL_CONTAINER_SUFFIXES:
        return True
    if path.name in SHELL_FILE_NAMES or path.name.startswith(("Dockerfile.", "Makefile.", "Procfile.")):
        return True
    return sample.startswith(b"#!")


def _discover_capability_paths(root: Path) -> tuple[list[Path], list[dict[str, Any]]]:
    candidates: list[Path] = []
    issues: list[dict[str, Any]] = []
    if root.is_file():
        raw_paths = [root]
    else:
        raw_paths = []
        for current, dirs, files in os.walk(root):
            dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not name.startswith(".cache")]
            raw_paths.extend(Path(current) / name for name in sorted(files))
    for path in raw_paths:
        try:
            stat = path.stat()
            with path.open("rb") as handle:
                sample = handle.read(4096)
        except OSError as exc:
            if _is_capability_candidate_path(path):
                issues.append({"code": "SEED003", "file": str(path), "message": f"cannot inspect source file: {exc}"})
            continue
        if not _is_capability_candidate_path(path, sample):
            continue
        if b"\x00" in sample:
            issues.append({"code": "SEED006", "file": str(path), "message": "candidate source file appears binary"})
            continue
        if stat.st_size > MAX_CAPABILITY_FILE_BYTES:
            issues.append(
                {
                    "code": "SEED005",
                    "file": str(path),
                    "message": f"candidate source file exceeds {MAX_CAPABILITY_FILE_BYTES} bytes",
                }
            )
            continue
        candidates.append(path)
    return candidates, issues


def _failed_payload(root: Path, code: str, message: str) -> dict[str, Any]:
    return {
        "tool": "dangerous_capability_seed",
        "scanner_version": SCANNER_VERSION,
        "status": "failed",
        "root": str(root),
        "files_considered": 0,
        "files_scanned": 0,
        "snapshot_digest": "",
        "discovered_total": 0,
        "family_totals": {},
        "records": [],
        "records_digest": records_digest([]),
        "issues": [{"code": code, "message": message}],
        "notice": "No census claim can be made for this target.",
    }


def write_seed_state(state_dir: Path, payload: dict[str, Any], *, scope: str = "repository") -> None:
    if not isinstance(payload.get("files_considered"), int) or payload["files_considered"] <= 0:
        raise ValueError("cannot write seed state without auditable source files")
    state_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = state_dir / "manifest.json"
    if not manifest_path.exists():
        raise ValueError("state-dir must contain manifest.json before seeding")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("state manifest must contain run_id before seeding")
    records = payload["records"]
    write_jsonl(state_dir / "dangerous-capability-seed.jsonl", records)
    summary = {
        "schema_version": "2.0",
        "census_completed": payload.get("status") == "ok",
        "tool": payload["tool"],
        "scanner_version": payload["scanner_version"],
        "root": payload["root"],
        "scope": scope,
        "files_considered": payload["files_considered"],
        "files_scanned": payload["files_scanned"],
        "snapshot_digest": payload["snapshot_digest"],
        "records_digest": payload["records_digest"],
        "required_families": sorted(SENTINEL_FAMILIES),
        "family_totals": payload["family_totals"],
        "discovered_total": payload["discovered_total"],
        "scan_issues": payload["issues"],
        "raw_seed_file": "dangerous-capability-seed.jsonl",
    }
    (state_dir / "dangerous-capability-census.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _merge_seed_ledgers(state_dir, records, run_id=run_id, scope=scope)


def _merge_seed_ledgers(
    state_dir: Path, records: list[dict[str, Any]], *, run_id: str, scope: str
) -> None:
    ledger_path = state_dir / "dangerous-capabilities.jsonl"
    evidence_path = state_dir / "evidence-observations.jsonl"
    existing_ledger = {
        row["id"]: row
        for row in read_jsonl(ledger_path)
        if isinstance(row.get("id"), str) and "_parse_error" not in row
    }
    existing_evidence = {
        row["id"]: row
        for row in read_jsonl(evidence_path)
        if isinstance(row.get("id"), str) and "_parse_error" not in row
    }
    seeded_ids = {record["id"] for record in records}
    merged_ledger = [
        row for rid, row in existing_ledger.items()
        if row.get("origin") == "manual" or rid in seeded_ids
    ]
    ledger_by_id = {row["id"]: row for row in merged_ledger}
    for record in records:
        evidence_id = f"evidence-{record['id']}"
        existing_evidence[evidence_id] = {
            "id": evidence_id,
            "run_id": run_id,
            "scope": scope,
            "owner": "dangerous_capability_seed",
            "freshness_status": "fresh_current",
            "kind": "dangerous_capability_seed",
            "family": record["family"],
            "location": record["location"],
            "source_digest": record["source_digest"],
            "seed_ref": record["id"],
        }
        current = ledger_by_id.get(record["id"], {})
        ledger_by_id[record["id"]] = {
            **record,
            **current,
            "id": record["id"],
            "run_id": run_id,
            "scope": scope,
            "owner": current.get("owner", "primary"),
            "freshness_status": "fresh_current",
            "evidence_refs": [evidence_id],
            "origin": "seed",
            "family": record["family"],
            "kind": record["kind"],
            "location": record["location"],
            "source_digest": record["source_digest"],
        }
    write_jsonl(ledger_path, sorted(ledger_by_id.values(), key=lambda row: row["id"]))
    write_jsonl(evidence_path, sorted(existing_evidence.values(), key=lambda row: row["id"]))


def records_digest(records: Iterable[dict[str, Any]]) -> str:
    canonical = "\n".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for record in records
    )
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def _snapshot_digest(file_fingerprints: Iterable[tuple[str, str]]) -> str:
    canonical = "\n".join(f"{path}\0{digest}" for path, digest in sorted(file_fingerprints))
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()


def _scan_python_with_status(text: str, path: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        issue = {
            "code": "SEED004",
            "file": path,
            "line": exc.lineno,
            "message": f"Python AST parse failed; fallback results are incomplete: {exc.msg}",
        }
        return _scan_python_fallback(text, path), issue

    return _scan_python_tree(tree, text, path), None


def _scan_python(text: str, path: str) -> list[dict[str, Any]]:
    records, _ = _scan_python_with_status(text, path)
    return records


def _scan_python_tree(tree: ast.AST, text: str, path: str) -> list[dict[str, Any]]:
    dynamic_aliases, module_aliases, process_aliases, session_aliases = _python_aliases(tree)
    hardcoded_names = _python_hardcoded_names(tree)

    lines = text.splitlines()
    records: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dynamic_kind = _python_dynamic_call_kind(node, dynamic_aliases, module_aliases)
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
            command_kind = _python_command_call_kind(node, module_aliases, process_aliases)
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
            session_kind = _session_call_kind(node, session_aliases)
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
                if keyword.arg and _is_signing_key_name(keyword.arg):
                    kind = (
                        "hardcoded_signing_key"
                        if _has_hardcoded_material(keyword.value, hardcoded_names)
                        else "indirect_signing_key_binding"
                    )
                    records.append(
                        _record(
                            "signing_material",
                            kind,
                            path,
                            node.lineno,
                            "<redacted signing material>",
                        )
                    )
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = _assignment_targets(node)
            if value is not None and any(_is_signing_key_target(target) for target in targets):
                if _has_hardcoded_material(value, hardcoded_names):
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
                else:
                    records.append(
                        _record(
                            "signing_material",
                            "indirect_signing_key_binding",
                            path,
                            node.lineno,
                            "<redacted indirect signing material>",
                        )
                    )
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if _is_signing_key_name(key.value) and _has_hardcoded_material(value, hardcoded_names):
                        records.append(
                            _record(
                                "signing_material",
                                "hardcoded_signing_key",
                                path,
                                node.lineno,
                                "<redacted hardcoded signing material>",
                            )
                        )
        elif isinstance(node, ast.Subscript) and _is_session_name(node.value, session_aliases):
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
        elif isinstance(node, ast.Compare) and any(_is_session_name(item, session_aliases) for item in node.comparators):
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


def _python_aliases(tree: ast.AST) -> tuple[dict[str, str], dict[str, str], dict[str, str], set[str]]:
    dynamic_aliases = {name: name for name in DYNAMIC_NAMES}
    module_aliases = {"builtins": "builtins", "importlib": "importlib", "subprocess": "subprocess", "os": "os", "asyncio": "asyncio", "flask": "flask"}
    process_aliases: dict[str, str] = {}
    session_aliases = {"session"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"builtins", "importlib", "subprocess", "os", "asyncio", "flask"}:
                    module_aliases[alias.asname or alias.name] = alias.name
                    if alias.name == "flask":
                        session_aliases.add(f"{alias.asname or alias.name}.session")
        elif isinstance(node, ast.ImportFrom):
            if node.module in {"builtins", "__builtins__"}:
                for alias in node.names:
                    if alias.name in DYNAMIC_NAMES:
                        dynamic_aliases[alias.asname or alias.name] = alias.name
            elif node.module == "subprocess":
                for alias in node.names:
                    if alias.name in SUBPROCESS_CALLS or alias.name in {"getoutput", "getstatusoutput"}:
                        process_aliases[alias.asname or alias.name] = f"subprocess.{alias.name}"
            elif node.module == "flask":
                for alias in node.names:
                    if alias.name == "session":
                        session_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            source = node.value
            if isinstance(source, ast.Name) and source.id in dynamic_aliases:
                dynamic_aliases[target] = dynamic_aliases[source.id]
            if isinstance(source, ast.Name) and source.id in session_aliases:
                session_aliases.add(target)
            if isinstance(source, ast.Attribute) and isinstance(source.value, ast.Name):
                module = module_aliases.get(source.value.id)
                if module in {"builtins"} and source.attr in DYNAMIC_NAMES:
                    dynamic_aliases[target] = source.attr
                if module == "subprocess" and source.attr in SUBPROCESS_CALLS:
                    process_aliases[target] = f"subprocess.{source.attr}"
                if f"{source.value.id}.{source.attr}" in session_aliases:
                    session_aliases.add(target)
    return dynamic_aliases, module_aliases, process_aliases, session_aliases


def _python_hardcoded_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        if not _has_hardcoded_material(node.value):
            continue
        for target in _assignment_targets(node):
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _python_dynamic_call_kind(
    node: ast.Call, dynamic_aliases: dict[str, str], module_aliases: dict[str, str]
) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        if func.id in dynamic_aliases:
            return f"python_{dynamic_aliases[func.id]}"
        if func.id == "__import__":
            return "python_dynamic_import"
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name) and module_aliases.get(func.value.id) == "builtins":
            if func.attr in DYNAMIC_NAMES:
                return f"python_{func.attr}"
        if isinstance(func.value, ast.Name) and module_aliases.get(func.value.id) == "importlib" and func.attr == "import_module":
            return "python_dynamic_import"
    if isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "getattr":
        if len(func.args) >= 2 and isinstance(func.args[1], ast.Constant):
            name = func.args[1].value
            if name in DYNAMIC_NAMES:
                return f"python_reflective_{name}"
    return None


def _python_command_call_kind(
    node: ast.Call, module_aliases: dict[str, str], process_aliases: dict[str, str]
) -> str | None:
    func = node.func
    qualified = ""
    if isinstance(func, ast.Name):
        qualified = process_aliases.get(func.id, "")
    elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        module = module_aliases.get(func.value.id)
        if module:
            qualified = f"{module}.{func.attr}"

    if qualified in {"os.system", "os.popen"}:
        return "python_os_command_string"
    if qualified in {"asyncio.create_subprocess_shell", "subprocess.getoutput", "subprocess.getstatusoutput"}:
        return "python_shell_command_string"
    if qualified.startswith("subprocess.") and qualified.rsplit(".", 1)[-1] in SUBPROCESS_CALLS:
        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                return "python_subprocess_shell_true"
        if _call_uses_shell_interpreter(node):
            return "python_shell_interpreter_command"
    return None


def _call_uses_shell_interpreter(node: ast.Call) -> bool:
    if not node.args:
        return False
    value = node.args[0]
    if isinstance(value, (ast.List, ast.Tuple)):
        constants = [item.value for item in value.elts if isinstance(item, ast.Constant)]
        if len(constants) >= 2:
            executable = str(constants[0]).rsplit("/", 1)[-1]
            return executable in {"sh", "bash", "zsh", "ksh"} and constants[1] == "-c"
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return bool(re.search(r"(?:^|/)(?:ba|z|k)?sh\s+-c(?:\s+|$)", value.value))
    return False


def _session_call_kind(node: ast.Call, session_aliases: set[str]) -> str | None:
    func = node.func
    if not isinstance(func, ast.Attribute) or not _is_session_name(func.value, session_aliases):
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


def _has_hardcoded_material(node: ast.AST, hardcoded_names: set[str] | None = None) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, bytes)) and bool(node.value)
    if isinstance(node, ast.Name) and hardcoded_names is not None:
        return node.id in hardcoded_names
    if isinstance(node, ast.BoolOp):
        return any(_has_hardcoded_material(value, hardcoded_names) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _has_hardcoded_material(node.left, hardcoded_names) or _has_hardcoded_material(node.right, hardcoded_names)
    return False


def _is_literal_fallback(node: ast.AST) -> bool:
    return isinstance(node, ast.BoolOp) and any(_has_hardcoded_material(value) for value in node.values)


def _is_session_name(node: ast.AST, session_aliases: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in session_aliases
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}" in session_aliases
    return False


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
            records.append(_record("shell_command_execution", "javascript_command_string", path, lineno, line))
    return records


def _scan_generic_code(text: str, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("//", "#", "*")):
            continue
        if GENERIC_DYNAMIC_RE.search(line):
            records.append(_record("dynamic_code_evaluation", "generic_dynamic_evaluation", path, lineno, line))
        if GENERIC_COMMAND_RE.search(line):
            records.append(_record("shell_command_execution", "generic_process_execution", path, lineno, line))
    return records


def _is_shell_container(path: Path, text: str) -> bool:
    if path.suffix.lower() in SHELL_SUFFIXES | POWERSHELL_SUFFIXES | SHELL_CONTAINER_SUFFIXES:
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
            records.append(_record("shell_command_execution", "shell_command_string", path, lineno, line))
        if path.lower().endswith(".ps1") and POWERSHELL_EVAL_RE.search(line):
            records.append(_record("dynamic_code_evaluation", "powershell_invoke_expression", path, lineno, line))
        if path.lower().endswith(".ps1") and POWERSHELL_COMMAND_RE.search(line):
            records.append(_record("shell_command_execution", "powershell_command_execution", path, lineno, line))
    return records


def _record(family: str, kind: str, path: str, line: int, snippet: str) -> dict[str, Any]:
    clean_snippet = " ".join(snippet.strip().split())[:240]
    source_digest = hashlib.sha256(clean_snippet.encode("utf-8", errors="replace")).hexdigest()
    identity = f"{family}\0{kind}\0{path}\0{line}\0{source_digest}".encode("utf-8", errors="replace")
    return {
        "id": "danger-" + hashlib.sha256(identity).hexdigest()[:16],
        "family": family,
        "kind": kind,
        "path": path,
        "line": line,
        "location": f"{path}:{line}",
        "symbol_or_snippet": clean_snippet,
        "source_digest": source_digest,
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
