# Safe Local Execution Boundary

Use this control whenever an audit needs to build, test, render, fuzz, or run
target-controlled code. Source inspection remains read-only and does not need
this execution path.

## Required boundary

Before execution, record `execution_policy` in `run-metadata.json` or the
equivalent run state. The policy must provide all of these controls:

- no external network; isolated loopback is allowed only for a local fixture;
- an empty environment populated from an explicit allowlist of safe values;
- a read-only target and toolchain;
- writes only below the assigned worker `scratch/` directory;
- explicit CPU, memory, process, file-size, disk, and wall-clock limits;
- dummy principals, fixtures, and secrets only.

Never run target-controlled installers, package scripts, repository scanner
wrappers, deployment commands, or hooks merely to inspect a repository. Do not
contact deployed endpoints, provider APIs, shared queues, registries, paid
services, production identities, or another user's data.

## Trusted connector network access

The target-execution sandbox above applies to target-controlled code. Trusted
installed requirements/SCA connectors may use a user-configured HTTPS service
and its dedicated credential within their declared capability. They may read
bounded dependency manifests or approved context without executing target code.
Never forward credentials to target commands, follow target-supplied endpoints,
or treat connector access as permission to run package scripts with network.

## Evidence promotion

Scratch output is target-controlled and cannot support a final finding by
itself. A trusted parent may promote a predeclared regular file only after the
process exits, using no-follow path traversal, exclusive destination creation,
link-count checks, and per-file and cumulative size limits. If the host cannot
enforce those checks, keep the result as source evidence or
`needs_validation`/coverage debt and record the exact promotion blocker.

Workers never write shared ledgers, retained reports, another worker's
directory, or the target tree. The supervisor owns promotion and shared-state
updates.

## Failure behavior

Missing sandbox controls do not reduce review scope and do not prove the target
safe. Preserve the source-grounded candidate, set the exact blocker, and give
one bounded local or owner-observed validation step. A failed payload or a
serializer/allowlist check cannot close a reachable dangerous capability by
itself.
