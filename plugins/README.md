# Security Code Audit Plugin Contract

`plugins/` contains extensions owned by `security-code-audit`. Every immediate child directory is one Code Audit plugin. These are not plugins discovered from the repository being audited.

## Layout

```text
plugins/
  plugin.schema.json
  README.md
  <plugin-id>/
    README.md                        # required user and operator guide
    plugin.json
    config.json
    .codex-plugin/plugin.json  # required when the plugin exposes MCP through Codex
    .mcp.json                  # optional MCP entry
    skills/                    # optional Skill entries
      <skill-id>/SKILL.md
    web/                       # optional MCP Apps resources
    server/                    # optional MCP implementation
```

`plugin.json` is the Code Audit entry point. `.codex-plugin/plugin.json`, `.mcp.json`, `SKILL.md`, and `ui://` resources keep their native Codex/MCP formats; the Code Audit manifest only declares when and why those entries participate in an audit.

## Manifest

```json
{
  "$schema": "../plugin.schema.json",
  "schemaVersion": "1.0",
  "id": "sample-requirements",
  "displayName": "Sample Requirements",
  "enabled": true,
  "capabilities": ["requirements-context"],
  "entrypoints": {
    "mcp": "./.mcp.json",
    "skills": ["./skills/audit-requirements-context/SKILL.md"],
    "web": "./web/index.html"
  },
  "config": "./config.json",
  "report": {
    "heading": "需求上下文",
    "guide": "./README.md"
  },
  "lifecycle": {
    "after": "architecture-and-change-recon",
    "before": "security-semantic-review",
    "failure": "continue"
  }
}
```

Rules:

- The directory name, `plugin.json.id`, and native Codex plugin name must match.
- Declare at least one `mcp` or `skills` entry. `web` is optional and requires `mcp`.
- Entrypoint and config paths start with `./`, resolve inside the plugin directory, and name existing files.
- Every plugin has a non-empty `README.md`. It is part of the plugin contract, not optional project prose.
- `config.json` is declarative. Store environment-variable names there, never credential values.
- The Code Audit core evaluates plugins by capability and lifecycle, not by a hard-coded provider name.
- `failure: continue` records an exact terminal status and continues the audit. It never narrows scope.
- `failure: coverage-debt` may add explicit coverage debt when a security conclusion genuinely depends on the unavailable plugin.
- `failure: abort` is reserved for organization-mandated controls and must not be used by optional context providers.

Each plugin README must document its capability, installation, safe defaults, optional user override file, authentication environment variables, verification procedure, normal usage, terminal/failure statuses, report presentation, security boundary, and development tests. Put provider-specific instructions in that README instead of expanding the Code Audit core documentation.

When a plugin supports a user-owned JSON override, its bundled `config.json` should declare a dedicated `configEnv` such as `SAMPLE_AUDIT_CONFIG`. The MCP entry must forward both that variable and every credential variable named by the config. The override file lives outside the installed plugin so a reinstall cannot erase user settings.

## Report Presentation

Every plugin declares `report`, so its results have a fixed, independent place in
the final report instead of being dissolved into other sections as cited data.

| Field | Meaning |
| --- | --- |
| `heading` | Exact `## <heading>` section title in the final report |
| `guide` | Plugin-local document whose "Report presentation" section describes the section content |
| `context` | Optional state-directory file proving the plugin ran in this audit; its presence makes the section mandatory |
| `summary` | Optional `{field, label}` list rendered as status lines from `context` |
| `rows` | Optional state-directory JSONL of per-item results; requires `context`, `rowKey`, and `columns` |
| `review` | Optional state-directory JSONL of local review decisions merged into rows by `rowKey` |
| `rowKey` | Field identifying one row in both `rows` and `review` |
| `columns` | `{field, label[, link]}` list rendered as one Markdown table; `link` names an `https://` URL field |

Render all declared sections from the current state directory:

```bash
python3 tools/plugin_report_render.py --run-dir <state-dir> --out <fragment.md>
```

Rules:

- Place plugin sections after `Coverage Debt` and before supplemental sections, in registry order.
- When `context` exists for the run, the section is mandatory even when the plugin failed or returned zero rows. Show the terminal status; an empty table never means clean.
- When `rows` is declared, the table lists every row from this run. Do not truncate, sample, or replace the table with a reference to state files.
- Plugin rows stay plugin results. Promoting one into `Confirmed Findings` or `Candidate Signals` still follows normal verification, and the row's `finding_ref` links to that entry. The row itself is never deleted.
- Cell values are untrusted remote data. The renderer escapes them so they cannot inject Markdown structure or links.
- `tools/report_gate_check.py --run-dir` fails with `REPORT060` when a section is missing and `REPORT061` when the row count differs.

## Discovery

Validate and list the trusted, bundled plugins:

```bash
python3 tools/audit_plugin_check.py
```

The root is fixed to this skill's own `plugins/` directory; the CLI has no target-root override. A target repository folder named `plugins/`, `connectors/`, or `skills/` remains untrusted audit input and is never an extension source.

## MCP Plugins

An MCP plugin uses native `.mcp.json` configuration and includes `.codex-plugin/plugin.json` so the host can register its tools before the audit starts. Code Audit discovery validates metadata only; it does not dynamically execute commands from manifests.

Use environment forwarding for temporary credentials and user configuration paths. If `config.json` names `tokenEnv` or `configEnv`, the same value must be allowlisted in the native `.mcp.json` entry. Credentials remain environment-only and must never appear in either bundled or user-owned JSON.

## Skill Plugins

Each skill entry points to a standard `<skill-id>/SKILL.md`. Keep activation guidance in frontmatter and audit-stage instructions in the body. The Code Audit core loads or invokes the skill only when its capability and lifecycle match the current run.

For `requirements-context`, invocation is automatic after Code Audit resolves the user-requested audit scope and completes architecture/change recon. A provider plugin must accept that derived context and must not require the user to make a second request or manually supply an MR/PR identifier. If the identifier is absent, use bounded Git, code-semantic, and architecture anchors so the remote provider can resolve the related change.

## Web Entries

`web` names the HTML source served by the plugin's MCP server. The corresponding MCP tool must advertise a `ui://` resource and `text/html;profile=mcp-app`; the file path alone does not make the UI executable.


For `dependency-sca`, invocation follows dependency recon and precedes coverage
verification. Derive project identity from the current scan target, retain
current-run status and input hashes, and reconcile remote advisories with local
manifests and reachability. A skill-based CLI adapter is supported without MCP;
no provider is required by the public framework. Follow
`references/shared/dependencies/sca-integration.md` from the skill root.
