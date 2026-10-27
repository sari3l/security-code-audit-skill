#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

from security_audit_tools.common import Issue, emit_json, issue_payload, read_json


PLUGIN_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
PHASES = {
    "audit-start": 0,
    "architecture-and-change-recon": 1,
    "security-semantic-review": 2,
    "coverage-verification": 3,
    "report-finalization": 4,
    "audit-complete": 5,
}
FAILURE_POLICIES = {"continue", "coverage-debt", "abort"}
TOP_LEVEL_FIELDS = {
    "$schema",
    "schemaVersion",
    "id",
    "displayName",
    "enabled",
    "capabilities",
    "entrypoints",
    "config",
    "report",
    "lifecycle",
}
ENTRYPOINT_FIELDS = {"mcp", "skills", "web"}
LIFECYCLE_FIELDS = {"after", "before", "failure"}
REPORT_FIELDS = {"heading", "guide", "context", "rows", "review", "rowKey", "summary", "columns"}
REPORT_DEPENDENCIES = {
    "rows": ("context", "rowKey", "columns"),
    "review": ("rows",),
    "rowKey": ("rows",),
    "columns": ("rows",),
    "summary": ("context",),
}
FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
STATE_ARTIFACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SENSITIVE_FIELDS = {
    "access_token",
    "api_key",
    "api_secret",
    "authorization",
    "client_secret",
    "cookie",
    "credentials",
    "password",
    "refresh_token",
    "secret",
    "token",
}


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return candidate != root


def _resolve_local_path(
    plugin_root: Path,
    value: Any,
    *,
    label: str,
    manifest_path: Path,
    issues: list[Issue],
) -> Path | None:
    if not isinstance(value, str) or not value.startswith("./"):
        issues.append(Issue("PLUGIN010", f"{label} must be a ./-prefixed path", file=str(manifest_path)))
        return None
    unresolved = plugin_root / value[2:]
    try:
        resolved = unresolved.resolve(strict=True)
    except OSError as exc:
        issues.append(Issue("PLUGIN011", f"{label} does not resolve: {exc}", file=str(manifest_path)))
        return None
    if not _inside(plugin_root.resolve(), resolved):
        issues.append(Issue("PLUGIN012", f"{label} resolves outside the plugin directory", file=str(manifest_path)))
        return None
    if not resolved.is_file():
        issues.append(Issue("PLUGIN013", f"{label} must name a file", file=str(manifest_path)))
        return None
    return resolved


def _contains_sensitive_field(value: Any) -> bool:
    if isinstance(value, list):
        return any(_contains_sensitive_field(item) for item in value)
    if not isinstance(value, dict):
        return False
    for key, child in value.items():
        normalized = str(key).lower().replace("-", "_")
        if normalized in SENSITIVE_FIELDS or _contains_sensitive_field(child):
            return True
    return False


def _read_object(path: Path, code: str, label: str, issues: list[Issue]) -> dict[str, Any] | None:
    try:
        value = read_json(path)
    except Exception as exc:  # noqa: BLE001 - stable validator diagnostics
        issues.append(Issue(code, f"{label} is invalid JSON: {exc}", file=str(path)))
        return None
    if not isinstance(value, dict):
        issues.append(Issue(code, f"{label} must contain an object", file=str(path)))
        return None
    return value


def _forwarded_environment_variables(mcp_payload: dict[str, Any]) -> set[str]:
    servers = mcp_payload.get("mcpServers", mcp_payload.get("mcp_servers"))
    if not isinstance(servers, dict):
        return set()
    forwarded: set[str] = set()
    for server in servers.values():
        if not isinstance(server, dict):
            continue
        env_vars = server.get("env_vars")
        if isinstance(env_vars, list):
            forwarded.update(item for item in env_vars if isinstance(item, str))
    return forwarded


def check_plugin(plugin_root: Path) -> tuple[dict[str, Any] | None, list[Issue]]:
    issues: list[Issue] = []
    readme_path = plugin_root / "README.md"
    resolved_readme: str | None = None
    if not readme_path.is_file():
        issues.append(Issue("PLUGIN032", "README.md is missing", file=str(readme_path)))
    else:
        try:
            if not readme_path.read_text(encoding="utf-8").strip():
                issues.append(Issue("PLUGIN033", "README.md must not be empty", file=str(readme_path)))
            else:
                resolved_readme = str(readme_path.resolve(strict=True))
        except (OSError, UnicodeError) as exc:
            issues.append(Issue("PLUGIN033", f"README.md is not readable UTF-8: {exc}", file=str(readme_path)))

    manifest_path = plugin_root / "plugin.json"
    if not manifest_path.is_file():
        return None, [Issue("PLUGIN001", "plugin.json is missing", file=str(manifest_path))]
    manifest = _read_object(manifest_path, "PLUGIN002", "plugin.json", issues)
    if manifest is None:
        return None, issues

    unsupported = sorted(set(manifest) - TOP_LEVEL_FIELDS)
    if unsupported:
        issues.append(Issue("PLUGIN003", f"unsupported manifest fields: {', '.join(unsupported)}", file=str(manifest_path)))
    if manifest.get("schemaVersion") != "1.0":
        issues.append(Issue("PLUGIN004", "schemaVersion must be '1.0'", file=str(manifest_path)))

    plugin_id = manifest.get("id")
    if not isinstance(plugin_id, str) or not PLUGIN_ID.fullmatch(plugin_id):
        issues.append(Issue("PLUGIN005", "id must use lowercase kebab-case", file=str(manifest_path)))
    elif plugin_id != plugin_root.name:
        issues.append(Issue("PLUGIN006", "id must match the plugin directory name", file=str(manifest_path)))
    if not isinstance(manifest.get("displayName"), str) or not manifest["displayName"].strip():
        issues.append(Issue("PLUGIN007", "displayName is required", file=str(manifest_path)))
    if not isinstance(manifest.get("enabled"), bool):
        issues.append(Issue("PLUGIN008", "enabled must be boolean", file=str(manifest_path)))

    capabilities = manifest.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or len(capabilities) != len(set(str(item) for item in capabilities))
        or any(not isinstance(item, str) or not PLUGIN_ID.fullmatch(item) for item in capabilities)
    ):
        issues.append(Issue("PLUGIN009", "capabilities must contain unique kebab-case names", file=str(manifest_path)))

    entrypoints = manifest.get("entrypoints")
    resolved_entries: dict[str, Any] = {}
    if not isinstance(entrypoints, dict):
        issues.append(Issue("PLUGIN014", "entrypoints must be an object", file=str(manifest_path)))
        entrypoints = {}
    else:
        unsupported_entries = sorted(set(entrypoints) - ENTRYPOINT_FIELDS)
        if unsupported_entries:
            issues.append(Issue("PLUGIN015", f"unsupported entrypoints: {', '.join(unsupported_entries)}", file=str(manifest_path)))
    if "mcp" not in entrypoints and "skills" not in entrypoints:
        issues.append(Issue("PLUGIN016", "entrypoints must declare mcp or skills", file=str(manifest_path)))
    if "web" in entrypoints and "mcp" not in entrypoints:
        issues.append(Issue("PLUGIN017", "web entry requires an mcp entry", file=str(manifest_path)))

    forwarded_env_vars: set[str] = set()
    if "mcp" in entrypoints:
        mcp_path = _resolve_local_path(
            plugin_root,
            entrypoints["mcp"],
            label="entrypoints.mcp",
            manifest_path=manifest_path,
            issues=issues,
        )
        if mcp_path:
            resolved_entries["mcp"] = str(mcp_path)
            mcp_payload = _read_object(mcp_path, "PLUGIN018", "MCP entry", issues)
            if mcp_payload is not None and not any(key in mcp_payload for key in ("mcpServers", "mcp_servers")):
                issues.append(Issue("PLUGIN019", "MCP entry must contain mcpServers or mcp_servers", file=str(mcp_path)))
            elif mcp_payload is not None:
                forwarded_env_vars = _forwarded_environment_variables(mcp_payload)
            native_manifest_path = plugin_root / ".codex-plugin" / "plugin.json"
            native_manifest = _read_object(native_manifest_path, "PLUGIN020", "native Codex plugin manifest", issues)
            if native_manifest is not None:
                if native_manifest.get("name") != plugin_id:
                    issues.append(Issue("PLUGIN021", "native Codex plugin name must match plugin id", file=str(native_manifest_path)))
                if native_manifest.get("mcpServers") != entrypoints["mcp"]:
                    issues.append(Issue("PLUGIN022", "native mcpServers must match entrypoints.mcp", file=str(native_manifest_path)))

    if "skills" in entrypoints:
        skill_values = entrypoints["skills"]
        if not isinstance(skill_values, list) or not skill_values:
            issues.append(Issue("PLUGIN023", "entrypoints.skills must be a non-empty array", file=str(manifest_path)))
        else:
            resolved_skills = []
            for index, value in enumerate(skill_values):
                skill_path = _resolve_local_path(
                    plugin_root,
                    value,
                    label=f"entrypoints.skills[{index}]",
                    manifest_path=manifest_path,
                    issues=issues,
                )
                if skill_path:
                    if skill_path.name != "SKILL.md":
                        issues.append(Issue("PLUGIN024", "skill entry must name SKILL.md", file=str(skill_path)))
                    resolved_skills.append(str(skill_path))
            resolved_entries["skills"] = resolved_skills

    if "web" in entrypoints:
        web_path = _resolve_local_path(
            plugin_root,
            entrypoints["web"],
            label="entrypoints.web",
            manifest_path=manifest_path,
            issues=issues,
        )
        if web_path:
            resolved_entries["web"] = str(web_path)

    config_path = _resolve_local_path(
        plugin_root,
        manifest.get("config"),
        label="config",
        manifest_path=manifest_path,
        issues=issues,
    )
    if config_path:
        config = _read_object(config_path, "PLUGIN025", "plugin config", issues)
        if config is not None and _contains_sensitive_field(config):
            issues.append(Issue("PLUGIN026", "plugin config cannot contain inline credential fields", file=str(config_path)))
        if config is not None and "mcp" in entrypoints:
            for field in ("configEnv", "tokenEnv"):
                env_name = config.get(field)
                if isinstance(env_name, str) and env_name not in forwarded_env_vars:
                    issues.append(
                        Issue(
                            "PLUGIN034",
                            f"config.{field} environment variable {env_name} is not allowlisted by the MCP entry",
                            file=str(config_path),
                        )
                    )

    report = _check_report(plugin_root, manifest.get("report"), manifest_path, issues)

    lifecycle = manifest.get("lifecycle")
    if not isinstance(lifecycle, dict):
        issues.append(Issue("PLUGIN027", "lifecycle must be an object", file=str(manifest_path)))
        lifecycle = {}
    else:
        unsupported_lifecycle = sorted(set(lifecycle) - LIFECYCLE_FIELDS)
        if unsupported_lifecycle:
            issues.append(Issue("PLUGIN028", f"unsupported lifecycle fields: {', '.join(unsupported_lifecycle)}", file=str(manifest_path)))
    after = lifecycle.get("after")
    before = lifecycle.get("before")
    if after not in PHASES or before not in PHASES:
        issues.append(Issue("PLUGIN029", "lifecycle phases are invalid", file=str(manifest_path)))
    elif PHASES[after] >= PHASES[before]:
        issues.append(Issue("PLUGIN030", "lifecycle.after must precede lifecycle.before", file=str(manifest_path)))
    if lifecycle.get("failure") not in FAILURE_POLICIES:
        issues.append(Issue("PLUGIN031", "lifecycle.failure is invalid", file=str(manifest_path)))

    descriptor = {
        "id": plugin_id,
        "display_name": manifest.get("displayName"),
        "enabled": manifest.get("enabled"),
        "capabilities": capabilities if isinstance(capabilities, list) else [],
        "readme": resolved_readme,
        "entrypoints": resolved_entries,
        "report": report,
        "lifecycle": lifecycle,
    }
    return descriptor, issues


def _check_report(
    plugin_root: Path, report: Any, manifest_path: Path, issues: list[Issue]
) -> dict[str, Any] | None:
    if not isinstance(report, dict):
        issues.append(Issue("PLUGIN040", "report must declare how plugin results appear in the final report", file=str(manifest_path)))
        return None
    unsupported = sorted(set(report) - REPORT_FIELDS)
    if unsupported:
        issues.append(Issue("PLUGIN041", f"unsupported report fields: {', '.join(unsupported)}", file=str(manifest_path)))
    heading = report.get("heading")
    if not isinstance(heading, str) or not heading.strip() or len(heading) > 80 or "\n" in heading:
        issues.append(Issue("PLUGIN042", "report.heading must be a single-line section title", file=str(manifest_path)))
    guide = _resolve_local_path(plugin_root, report.get("guide"), label="report.guide", manifest_path=manifest_path, issues=issues)
    for field, required in REPORT_DEPENDENCIES.items():
        missing = [name for name in required if field in report and name not in report]
        if missing:
            issues.append(Issue("PLUGIN043", f"report.{field} requires {', '.join('report.' + name for name in missing)}", file=str(manifest_path)))
    for field in ("context", "rows", "review"):
        if field in report and (not isinstance(report[field], str) or not STATE_ARTIFACT.fullmatch(report[field])):
            issues.append(Issue("PLUGIN044", f"report.{field} must be a file name inside the audit state directory", file=str(manifest_path)))
    if "rowKey" in report and (not isinstance(report["rowKey"], str) or not FIELD_NAME.fullmatch(report["rowKey"])):
        issues.append(Issue("PLUGIN045", "report.rowKey must be a snake_case field name", file=str(manifest_path)))
    for field in ("summary", "columns"):
        if field in report and not _valid_field_list(report[field]):
            issues.append(Issue("PLUGIN046", f"report.{field} must be a non-empty list of {{field, label[, link]}} objects", file=str(manifest_path)))
    resolved = {key: value for key, value in report.items() if key in REPORT_FIELDS}
    resolved["guide"] = str(guide) if guide else None
    return resolved


def _valid_field_list(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        if not isinstance(item, dict) or set(item) - {"field", "label", "link"}:
            return False
        if not isinstance(item.get("field"), str) or not FIELD_NAME.fullmatch(item["field"]):
            return False
        label = item.get("label")
        if not isinstance(label, str) or not label.strip() or len(label) > 40 or "|" in label:
            return False
        if "link" in item and (not isinstance(item["link"], str) or not FIELD_NAME.fullmatch(item["link"])):
            return False
    return True


def check_plugins(plugins_root: Path) -> tuple[list[dict[str, Any]], list[Issue]]:
    if not plugins_root.is_dir():
        return [], [Issue("PLUGIN000", "plugins root is unavailable", file=str(plugins_root))]
    descriptors: list[dict[str, Any]] = []
    issues: list[Issue] = []
    for entry in sorted(plugins_root.iterdir(), key=lambda item: item.name):
        if entry.name.startswith(".") or not entry.is_dir():
            continue
        descriptor, plugin_issues = check_plugin(entry)
        if descriptor is not None:
            descriptors.append(descriptor)
        issues.extend(plugin_issues)
    return descriptors, issues


def main() -> int:
    default_root = Path(__file__).resolve().parents[1] / "plugins"
    parser = argparse.ArgumentParser(
        description="Validate trusted plugins bundled with this security-code-audit installation."
    )
    parser.parse_args()

    plugins_root = default_root.resolve()
    plugins, issues = check_plugins(plugins_root)
    payload = issue_payload(
        "audit_plugin_check",
        issues,
        {
            "plugins_root": str(plugins_root),
            "plugin_count": len(plugins),
            "enabled_plugins": sorted(
                plugin["id"] for plugin in plugins if plugin.get("enabled") is True
            ),
            "plugins": plugins,
        },
    )
    emit_json(payload)
    return 1 if payload["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
