#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from security_audit_tools.capability import SeedMatch
from security_audit_tools.common import (
    emit_json,
    iter_text_files,
    line_excerpt,
    positive_int,
    stable_id,
    write_jsonl,
)


URL_RE = re.compile(r"https?://[^\s`'\"|)]+", re.IGNORECASE)
CODE_SPAN_RE = re.compile(r"`([^`\n]{3,200})`")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed advisory capability-map observations.")
    parser.add_argument("target", type=Path)
    parser.add_argument("--out", type=Path, help="Directory for JSONL outputs.")
    parser.add_argument("--max-file-bytes", type=positive_int, default=1_000_000)
    args = parser.parse_args()

    raw, capabilities, paths, claims, unmapped = seed(args.target, max_file_bytes=args.max_file_bytes)
    summary = {
        "raw_observations": len(raw),
        "capabilities": len(capabilities),
        "capability_paths": len(paths),
        "capability_claims": len(claims),
        "unmapped_signals": len(unmapped),
    }
    if args.out:
        write_jsonl(args.out / "raw-observations.jsonl", raw)
        write_jsonl(args.out / "capabilities.jsonl", capabilities)
        write_jsonl(args.out / "capability-paths.jsonl", paths)
        write_jsonl(args.out / "capability-claims.jsonl", claims)
        write_jsonl(args.out / "unmapped-signals.jsonl", unmapped)
    emit_json(
        {
            "tool": "capability_map_seed",
            "status": "ok",
            "summary": summary,
            "open_world_notice": (
                "Seeder output is advisory. Unmatched text is not safe; raw and unmapped "
                "signals remain valid inputs for LLM/human review."
            ),
        }
    )
    return 0


def seed(target: Path, *, max_file_bytes: int):
    root = target.resolve()
    raw: list[dict] = []
    capabilities: list[dict] = []
    paths: list[dict] = []
    claims: list[dict] = []
    unmapped: list[dict] = []

    for path in iter_text_files(root, max_bytes=max_file_bytes):
        rel = _relative(path, root)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            excerpt = line_excerpt(line)
            if not excerpt:
                continue
            lowered = excerpt.lower()
            matches = _classify_line(excerpt, lowered)
            claim_matches = _claim_line(excerpt, lowered)
            code_spans = CODE_SPAN_RE.findall(line)
            unknown_spans = _unknown_code_spans(code_spans, matches)
            if not matches and not claim_matches and not unknown_spans:
                continue
            raw_id = stable_id("raw", rel, lineno, excerpt)
            raw_record = {
                "id": raw_id,
                "kind": "raw_observation",
                "file": rel,
                "line_start": lineno,
                "line_end": lineno,
                "raw_text": excerpt,
                "freshness_status": "fresh_current",
            }
            raw.append(raw_record)
            for index, match in enumerate(matches):
                cap_id = stable_id("cap", rel, lineno, index, match.reason, excerpt)
                capabilities.append(
                    match.to_capability(
                        record_id=cap_id,
                        scope=f"{rel}:{lineno}",
                        evidence_ref=raw_id,
                    )
                )
                paths.append(
                    {
                        "id": stable_id("path", cap_id),
                        "capability_id": cap_id,
                        "scope": f"{rel}:{lineno}",
                        "source": list(match.sources),
                        "sink": list(match.sinks),
                        "effects": list(match.effects),
                        "path_status": match.path_status,
                        "freshness_status": "fresh_current",
                        "evidence_refs": [raw_id],
                    }
                )
            for claim in claim_matches:
                claims.append(
                    {
                        "id": stable_id("claim", rel, lineno, claim),
                        "scope": f"{rel}:{lineno}",
                        "claim": claim,
                        "freshness_status": "fresh_current",
                        "evidence_refs": [raw_id],
                    }
                )
            for span in unknown_spans:
                unmapped.append(
                    {
                        "id": stable_id("sig", rel, lineno, span),
                        "kind": "unmapped_signal",
                        "scope": f"{rel}:{lineno}",
                        "file": rel,
                        "line_start": lineno,
                        "line_end": lineno,
                        "raw_text": span,
                        "reason": "command-like code span did not match known capability patterns",
                        "normalized_labels": ["schema_gap", "custom:unmapped_command"],
                        "freshness_status": "fresh_current",
                        "evidence_refs": [raw_id],
                    }
                )
    return raw, capabilities, paths, claims, unmapped


def _classify_line(excerpt: str, lowered: str) -> list[SeedMatch]:
    matches: list[SeedMatch] = []
    urls = tuple(URL_RE.findall(excerpt))
    negative_context = _is_negative_or_educational_context(lowered)
    status = "negative_evidence" if negative_context else "candidate"
    if re.search(r"\b(curl|wget)\b[^`'\"]{0,220}\|\s*(bash|sh|zsh|python|perl|ruby)\b", lowered):
        matches.append(
            SeedMatch(
                reason="remote download piped to interpreter",
                effects=("net_read", "proc_exec"),
                sources=("operator_instruction", "remote_content"),
                sinks=("network", "process"),
                resources=urls,
                path_status=status,
            )
        )
    elif re.search(r"\b(curl|wget)\b", lowered) and urls:
        matches.append(
            SeedMatch(
                reason="network fetch command",
                effects=("net_read",),
                sources=("operator_instruction",),
                sinks=("network",),
                resources=urls,
                path_status=status,
            )
        )
    if re.search(r"\b(eval|exec|python\s+-c|node\s+-e|bash\s+-c|sh\s+-c)\b", lowered):
        matches.append(
            SeedMatch(
                reason="dynamic code or shell execution",
                effects=("code_eval", "proc_exec"),
                sources=("operator_instruction",),
                sinks=("process",),
                path_status=status,
            )
        )
    if re.search(r"\b(launchctl|crontab|systemctl|plist|bashrc|zshrc|profile)\b", lowered):
        matches.append(
            SeedMatch(
                reason="startup or persistence mutation",
                effects=("persistence", "fs_write"),
                sources=("operator_instruction",),
                sinks=("host_startup", "filesystem"),
                path_status=status,
            )
        )
    if re.search(r"\b(pip|npm|yarn|pnpm|gem|cargo)\s+.*\b(global|-g|--force|--user|install)\b", lowered):
        matches.append(
            SeedMatch(
                reason="dependency or global environment mutation",
                effects=("dependency_mutation", "fs_write"),
                sources=("operator_instruction",),
                sinks=("dependency_environment", "filesystem"),
                path_status=status,
            )
        )
    if re.search(r"\b(api[_-]?key|token|secret|password|openai_api_key|anthropic_api_key)\b", lowered):
        matches.append(
            SeedMatch(
                reason="credential or secret reference",
                effects=("env_read",),
                sources=("secret", "environment"),
                sinks=("process_environment",),
                path_status=status,
            )
        )
    if re.search(r"(~/\.ssh|id_rsa|private key|\.aws/credentials|\.docker/config)", lowered):
        matches.append(
            SeedMatch(
                reason="sensitive local credential file reference",
                effects=("fs_read",),
                sources=("sensitive_local", "secret"),
                sinks=("filesystem",),
                path_status=status,
            )
        )
    if re.search(r"(chrome/default|google/chrome|browser profile|cookies|saved login)", lowered):
        matches.append(
            SeedMatch(
                reason="browser profile or saved-session access",
                effects=("browser_profile_access", "fs_read"),
                sources=("sensitive_local",),
                sinks=("browser_profile", "filesystem"),
                path_status=status,
            )
        )
    if re.search(r"\b(llm|agent|tool call|browser-use|chat/completions|responses api)\b", lowered):
        matches.append(
            SeedMatch(
                reason="agent or LLM call surface",
                effects=("agent_call",),
                sources=("operator_instruction",),
                sinks=("agent",),
                path_status=status,
            )
        )
    return matches


def _is_negative_or_educational_context(lowered: str) -> bool:
    return bool(
        re.search(
            r"\b(do not|don't|never|avoid|forbid|forbidden|example|examples|educational|defensive|warning)\b",
            lowered,
        )
    )


def _claim_line(excerpt: str, lowered: str) -> list[str]:
    claims: list[str] = []
    if re.search(r"\b(no network|no-network|offline|local only|local-only)\b", lowered):
        claims.append("no_network" if "network" in lowered or "offline" in lowered else "local_only")
    if re.search(r"\b(read only|read-only)\b", lowered):
        claims.append("read_only")
    if re.search(r"\b(no file write|no filesystem write|no fs write|no_fs_write)\b", lowered):
        claims.append("no_fs_write")
    if re.search(r"\b(credential bound|credential-bound|scoped credential)\b", lowered):
        claims.append("credential_bound")
    return sorted(set(claims))


def _unknown_code_spans(spans: list[str], matches: list[SeedMatch]) -> list[str]:
    if matches:
        known = " ".join(resource for match in matches for resource in match.resources)
    else:
        known = ""
    unknown: list[str] = []
    known_commands = re.compile(
        r"\b(curl|wget|eval|exec|python|node|bash|sh|launchctl|crontab|systemctl|pip|npm|yarn|pnpm)\b",
        re.IGNORECASE,
    )
    for span in spans:
        compact = line_excerpt(span, limit=200)
        if compact in known or known_commands.search(compact):
            continue
        first = compact.split(maxsplit=1)[0]
        if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", first) and ("_" in first or "-" in first):
            unknown.append(compact)
    return unknown


def _relative(path: Path, root: Path) -> str:
    try:
        base = root if root.is_dir() else root.parent
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.name


if __name__ == "__main__":
    raise SystemExit(main())
