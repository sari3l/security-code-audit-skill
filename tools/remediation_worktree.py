#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hmac


def run_git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise RuntimeError(message)
    return result.stdout.strip()


def run_git_result(root: Path, *args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_git_raw(root: Path, *args: str) -> str:
    result = run_git_result(root, *args)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise RuntimeError(message)
    return result.stdout


def safe_run_id(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-.").lower()
    if not normalized:
        raise argparse.ArgumentTypeError("run id must contain a letter or digit")
    return normalized[:80]


def ensure_repository_has_no_custom_filters(repository_root: Path) -> None:
    tracked = run_git_raw(repository_root, "ls-files", "-z").split("\0")
    paths = [path for path in tracked if path]
    for offset in range(0, len(paths), 500):
        chunk = paths[offset : offset + 500]
        output = run_git_raw(repository_root, "check-attr", "-z", "filter", "--", *chunk).split("\0")
        for index in range(0, len(output) - 2, 3):
            file_path, attribute, value = output[index : index + 3]
            if attribute == "filter" and value not in {"", "unspecified", "unset"}:
                raise RuntimeError(
                    f"custom Git filter blocks isolated worktree creation: {file_path} -> {value}"
                )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_session(path: Path, payload: dict[str, Any], *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if exclusive:
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        return
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(path)


def read_session(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != "remediation-session.v1":
        raise RuntimeError("invalid remediation session")
    return payload


def read_json_object(path: Path, label: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} must contain an object")
    return payload


def validate_finding_refs(session_file: Path, run_id: str, finding_refs: list[str]) -> list[str]:
    if not finding_refs:
        raise RuntimeError("at least one approved finding ref is required")
    run_dir = session_file.resolve().parent
    manifest = read_json_object(run_dir / "manifest.json", "manifest.json")
    configured = manifest.get("findings_path")
    if not isinstance(configured, str) or not configured.strip():
        raise RuntimeError("manifest findings_path is required for remediation")
    findings_path = Path(configured)
    if not findings_path.is_absolute():
        findings_path = run_dir / findings_path
    index: dict[str, dict[str, Any]] = {}
    with findings_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            finding = json.loads(line)
            if not isinstance(finding, dict):
                raise RuntimeError(f"canonical finding row {line_number} is not an object")
            for identity in (finding.get("id"), finding.get("fingerprint")):
                if isinstance(identity, str) and identity:
                    index[identity] = finding

    normalized_refs = sorted(set(finding_refs))
    for finding_ref in normalized_refs:
        finding = index.get(finding_ref)
        if finding is None:
            raise RuntimeError(f"selected finding ref does not resolve: {finding_ref}")
        if finding.get("schema_version") != "finding.v1" or finding.get("run_id") != run_id:
            raise RuntimeError(f"selected finding is not canonical for this run: {finding_ref}")
        if str(finding.get("maturity", "")).strip().casefold() != "confirmed":
            raise RuntimeError(f"automatic remediation requires a Confirmed finding: {finding_ref}")
        minimal_fix = finding.get("minimal_fix")
        if minimal_fix in (None, "", [], {}) or (isinstance(minimal_fix, str) and not minimal_fix.strip()):
            raise RuntimeError(f"confirmed finding has no concrete minimum remediation: {finding_ref}")
    return normalized_refs


def create_worktree(target: Path, run_id: str, session_file: Path, authorization: str) -> dict[str, Any]:
    resolved_target = target.resolve(strict=True)
    repository_root = Path(run_git(resolved_target, "rev-parse", "--show-toplevel")).resolve()
    branch = run_git(repository_root, "branch", "--show-current")
    if not branch:
        raise RuntimeError("detached HEAD is not eligible for automatic remediation")
    head = run_git(repository_root, "rev-parse", "HEAD")
    if run_git(repository_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("source worktree is not clean; preserve existing changes and stop")
    ensure_repository_has_no_custom_filters(repository_root)

    repair_branch = f"security-code-audit/fix-{run_id}"
    existing = run_git_result(repository_root, "show-ref", "--verify", "--quiet", f"refs/heads/{repair_branch}")
    if existing.returncode == 0:
        raise RuntimeError(f"repair branch already exists: {repair_branch}")

    parent = repository_root.parent
    base_name = f"{repository_root.name}-security-fix-{run_id}"
    worktree = parent / base_name
    suffix = 2
    while worktree.exists():
        worktree = parent / f"{base_name}-{suffix}"
        suffix += 1

    result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(repository_root),
            "worktree",
            "add",
            "-b",
            repair_branch,
            str(worktree),
            head,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "git worktree add failed"
        raise RuntimeError(message)

    payload: dict[str, Any] = {
        "schema_version": "remediation-session.v1",
        "status": "created",
        "run_id": run_id,
        "created_at": utc_now(),
        "start_authorization": authorization,
        "repository_root": str(repository_root),
        "source_branch": branch,
        "source_head": head,
        "repair_branch": repair_branch,
        "worktree": str(worktree.resolve()),
        "selected_finding_refs": [],
        "review": {
            "status": "not_snapshotted",
            "diff_digest": None,
            "changed_files": [],
            "validation_summary": None,
            "reaudit_summary": None,
            "proposed_commit_message": None,
        },
        "final_acceptance": {
            "accepted": False,
            "accepted_at": None,
            "reviewed_diff_digest": None,
            "receipt_sha256": None,
        },
        "integration": {
            "status": "not_started",
            "commit": None,
            "merge": None,
        },
    }
    try:
        write_session(session_file.resolve(), payload, exclusive=True)
    except Exception:
        run_git_result(repository_root, "worktree", "remove", "--force", str(worktree))
        run_git_result(repository_root, "branch", "-D", repair_branch)
        raise
    return payload


def changed_paths(worktree: Path) -> list[str]:
    output = run_git_raw(worktree, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    tokens = output.split("\0")
    paths: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if not token:
            continue
        status = token[:2]
        file_path = token[3:]
        if status[0] in {"R", "C"} and index < len(tokens):
            file_path = tokens[index]
            index += 1
        if file_path:
            paths.append(file_path)
    return sorted(set(paths))


def repair_digest(worktree: Path) -> tuple[str, list[str]]:
    paths = changed_paths(worktree)
    if not paths:
        raise RuntimeError("repair worktree has no changes to review")
    if any(path == "output" or path.startswith("output/") for path in paths):
        raise RuntimeError("generated audit artifacts must not be included in a repair")
    digest = hashlib.sha256()
    digest.update(run_git_raw(worktree, "diff", "--no-ext-diff", "--binary", "HEAD").encode())
    untracked = run_git_raw(worktree, "ls-files", "--others", "--exclude-standard", "-z").split("\0")
    for relative in sorted(path for path in untracked if path):
        full_path = worktree / relative
        digest.update(relative.encode())
        digest.update(b"\0")
        if full_path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.readlink(full_path).encode())
        else:
            executable = full_path.stat().st_mode & 0o111
            digest.update(f"regular-executable:{bool(executable)}\0".encode())
            digest.update(full_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest(), paths


def validate_session_identity(session: dict[str, Any]) -> tuple[Path, Path]:
    source = Path(session["repository_root"]).resolve(strict=True)
    worktree = Path(session["worktree"]).resolve(strict=True)
    if run_git(worktree, "branch", "--show-current") != session["repair_branch"]:
        raise RuntimeError("repair worktree branch no longer matches the session")
    return source, worktree


def snapshot_session(
    session_file: Path,
    message: str,
    finding_refs: list[str],
    validation_summary: str,
    reaudit_summary: str,
) -> dict[str, Any]:
    session = read_session(session_file)
    _, worktree = validate_session_identity(session)
    finding_refs = validate_finding_refs(session_file, session["run_id"], finding_refs)
    if run_git(worktree, "rev-parse", "HEAD") != session["source_head"]:
        raise RuntimeError("repair branch contains an unreviewed commit")
    digest, paths = repair_digest(worktree)
    session["selected_finding_refs"] = finding_refs
    session["review"] = {
        "status": "pending_user",
        "snapshotted_at": utc_now(),
        "diff_digest": digest,
        "changed_files": paths,
        "validation_summary": validation_summary[:4000],
        "reaudit_summary": reaudit_summary[:4000],
        "proposed_commit_message": message[:500],
    }
    session["final_acceptance"] = {
        "accepted": False,
        "accepted_at": None,
        "reviewed_diff_digest": None,
        "receipt_sha256": None,
    }
    session["status"] = "awaiting_final_acceptance"
    write_session(session_file, session)
    return session


def accept_session(session_file: Path, reviewed_digest: str) -> dict[str, Any]:
    session = read_session(session_file)
    _, worktree = validate_session_identity(session)
    validate_finding_refs(session_file, session["run_id"], session.get("selected_finding_refs", []))
    current_digest, _ = repair_digest(worktree)
    expected_digest = session.get("review", {}).get("diff_digest")
    if not expected_digest or reviewed_digest != expected_digest or current_digest != expected_digest:
        raise RuntimeError("repair diff changed after review; snapshot and review it again")
    receipt = secrets.token_urlsafe(32)
    session["final_acceptance"] = {
        "accepted": True,
        "accepted_at": utc_now(),
        "reviewed_diff_digest": reviewed_digest,
        "receipt_sha256": hashlib.sha256(receipt.encode()).hexdigest(),
    }
    session["review"]["status"] = "accepted"
    session["status"] = "accepted_for_integration"
    write_session(session_file, session)
    return {"session": session, "integration_receipt": receipt}


def ensure_no_custom_filters(worktree: Path, paths: list[str]) -> None:
    if not paths:
        return
    output = run_git_raw(worktree, "check-attr", "-z", "filter", "--", *paths).split("\0")
    for index in range(0, len(output) - 2, 3):
        file_path, attribute, value = output[index : index + 3]
        if attribute == "filter" and value not in {"", "unspecified", "unset"}:
            raise RuntimeError(f"custom Git filter blocks automatic integration: {file_path} -> {value}")


def integrate_session(session_file: Path, integration_receipt: str) -> dict[str, Any]:
    session = read_session(session_file)
    source, worktree = validate_session_identity(session)
    validate_finding_refs(session_file, session["run_id"], session.get("selected_finding_refs", []))
    acceptance = session.get("final_acceptance", {})
    expected_digest = acceptance.get("reviewed_diff_digest")
    if not acceptance.get("accepted") or not expected_digest:
        raise RuntimeError("explicit final acceptance is required before integration")
    expected_receipt = acceptance.get("receipt_sha256")
    supplied_receipt = hashlib.sha256(integration_receipt.encode()).hexdigest()
    if not isinstance(expected_receipt, str) or not hmac.compare_digest(expected_receipt, supplied_receipt):
        raise RuntimeError("current-turn integration receipt is required; review and accept again")
    current_digest, paths = repair_digest(worktree)
    if current_digest != expected_digest:
        raise RuntimeError("repair diff changed after final acceptance")
    if run_git(source, "branch", "--show-current") != session["source_branch"]:
        raise RuntimeError("original current branch changed after audit")
    if run_git(source, "rev-parse", "HEAD") != session["source_head"]:
        raise RuntimeError("original HEAD changed after audit")
    if run_git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("original source worktree is no longer clean")
    if run_git(worktree, "rev-parse", "HEAD") != session["source_head"]:
        raise RuntimeError("repair branch contains an unreviewed commit")
    ensure_no_custom_filters(worktree, paths)

    add_result = run_git_result(worktree, "add", "--all")
    if add_result.returncode != 0:
        raise RuntimeError(add_result.stderr.strip() or "git add failed")
    message = session.get("review", {}).get("proposed_commit_message")
    if not isinstance(message, str) or not message.strip():
        raise RuntimeError("accepted commit message is missing")
    commit_result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgSign=false",
            "-C",
            str(worktree),
            "commit",
            "--no-verify",
            "--no-gpg-sign",
            "-m",
            message,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if commit_result.returncode != 0:
        raise RuntimeError(commit_result.stderr.strip() or commit_result.stdout.strip() or "git commit failed")
    commit = run_git(worktree, "rev-parse", "HEAD")
    session["integration"] = {"status": "commit_created", "commit": commit, "merge": None}
    session["status"] = "commit_created"
    write_session(session_file, session)

    merge_result = subprocess.run(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(source),
            "merge",
            "--ff-only",
            session["repair_branch"],
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if merge_result.returncode != 0:
        session["integration"] = {
            "status": "commit_created_merge_blocked",
            "commit": commit,
            "merge": merge_result.stderr.strip() or merge_result.stdout.strip(),
        }
        session["status"] = "merge_blocked"
        write_session(session_file, session)
        raise RuntimeError(f"commit {commit} created but fast-forward merge was blocked")
    session["integration"] = {"status": "merged", "commit": commit, "merge": "fast_forward"}
    session["status"] = "merged"
    write_session(session_file, session)
    return session


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an isolated Code Audit remediation worktree.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("target_root", type=Path)
    create.add_argument("--run-id", required=True, type=safe_run_id)
    create.add_argument("--session-file", required=True, type=Path)
    create.add_argument("--authorization", choices=("prompt", "auto-fix"), required=True)
    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("session_file", type=Path)
    snapshot.add_argument("--message", required=True)
    snapshot.add_argument("--finding-ref", action="append", default=[])
    snapshot.add_argument("--validation-summary", default="")
    snapshot.add_argument("--reaudit-summary", default="")
    accept = subparsers.add_parser("accept")
    accept.add_argument("session_file", type=Path)
    accept.add_argument("--reviewed-digest", required=True)
    integrate = subparsers.add_parser("integrate")
    integrate.add_argument("session_file", type=Path)
    integrate.add_argument("--integration-receipt", required=True)
    args = parser.parse_args()

    try:
        if args.command == "create":
            payload = create_worktree(
                args.target_root,
                args.run_id,
                args.session_file,
                args.authorization,
            )
        elif args.command == "snapshot":
            payload = snapshot_session(
                args.session_file,
                args.message,
                args.finding_ref,
                args.validation_summary,
                args.reaudit_summary,
            )
        elif args.command == "accept":
            payload = accept_session(args.session_file, args.reviewed_digest)
        else:
            payload = integrate_session(args.session_file, args.integration_receipt)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        json.dump({"status": "blocked", "error": str(exc)}, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 2
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
