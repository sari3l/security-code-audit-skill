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

## Future Outbound Fetching

If this skill later gains outbound SCA access:
- prefer the repo's primary SCA source over multiple overlapping feeds
- fetch only the current project or image scope
- keep raw scanner output as an artifact, but summarize normalized findings in the report
- do not let remote SCA replace local review of vendored libraries, lock-file drift, or runtime reachability
