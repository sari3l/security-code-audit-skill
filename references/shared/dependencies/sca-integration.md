# External SCA Integration

Use this file whenever dependency findings come from a remote SCA platform, repository scanner, CI artifact, SBOM service, or future outbound API call.

## Purpose

External SCA is useful for:
- ecosystems without strong native audit tooling
- central policy and advisory feeds
- container and OS package visibility
- transitive dependency enrichment

It is not a substitute for local context. Always reconcile scanner output with the repo actually being audited.

## Required Normalization Fields

For each dependency issue, record:
- scanner source and scan time
- ecosystem
- package name
- affected version and fixed version
- advisory ID and link or source name
- severity from the scanner
- direct vs transitive status
- manifest or lock-file path when known
- runtime, dev-only, test-only, build-only, or unknown usage

## Validation Rules

- Do not blindly trust scanner severity if the package is not present in the current repo state.
- Do not keep findings that only match a different branch, image, or stale lock file.
- Deduplicate native audit and external SCA results by ecosystem plus package plus affected version plus advisory.
- Re-evaluate severity when the package is unreachable, dev-only, or blocked by deployment shape.
- Upgrade severity when the dependency issue compounds a code finding such as exposed debug mode, unsafe file parsing, or weak auth.

## Evidence Rules

Every dependency finding sourced from SCA should still include:
- the manifest or lock file that ties the issue to the repo
- the scanner source
- the package path or dependency chain if available
- the minimal upgrade, removal, or pinning action

## Installed Dependency Plugins

After architecture/change recon, select enabled `dependency-sca` plugins from
this skill's validated registry. Load the selected trusted skill entry; never
execute target-repository plugins, scanner wrappers, or package scripts. A CLI
skill entry is sufficient when it provides project-scoped scan submission,
polling, and machine-readable results. MCP is optional.

Bind the project to the current target's namespace/project, preferably its Git
origin. An explicit user override wins; never silently use a global/default
project left over from another scan. Record `sca-context.json` with `run_id`,
target, provider, project, timestamps, input hashes, exact terminal status, and
references to this run's raw and normalized artifacts. No configured provider
records `not_configured` and continues local review. Only a current successful
scan supports an SCA result; missing authentication, unsupported inputs, parser
warnings, timeouts, partial, failed, or stale-source results preserve limitations
and dependency coverage debt. A zero-finding response proves only the scanner's
matching result for the submitted inputs.

Remote findings start as candidates. Input-file provenance is not an exact
package-to-manifest mapping; preserve unknown scope, dependency path, directness,
and reachability until local inspection resolves them. Never write remote
candidates directly into canonical confirmed findings or bypass verification.

## Report Section

SCA results get their own report section, declared by the plugin's
`plugin.json.report` and described in its README. They are not only cited
data inside other sections. Render the section with `tools/plugin_report_render.py
--run-dir <state-dir>`. It lists every remote result with its local
review disposition, plus the scan status. Keep `sca-review.jsonl` decisions
separate from the adapter's raw rows. Promoted rows also appear in
`已确认漏洞` or `候选信号` and link back through `finding_ref`.

## Outbound Fetching

When the user configures an outbound SCA connector:
- prefer the repo's primary SCA source over multiple overlapping feeds
- fetch only the current project or image scope
- keep raw scanner output as an artifact, but summarize normalized findings in the report
- do not let remote SCA replace local review of vendored libraries, lock-file drift, or runtime reachability
