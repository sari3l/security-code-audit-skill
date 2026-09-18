# Shell Code Loading And Interpreted Configuration

Shell `source` and `.` execute a file in the current shell process. A file named `.env` is code, not dotenv data, when loaded this way: command substitutions, process substitutions, expansions, functions, traps, and shell commands run with the script's identity and environment.

## Enumerate First

- `source file` and `. file`, including variable paths and relative paths
- shell `eval`, `sh -c`, `bash -c`, `zsh -c`, and wrappers that construct command strings
- command and process substitution in files later interpreted by a shell
- Makefiles, Procfiles, systemd `Exec*`, Docker entrypoints, CI `run` blocks, deployment scripts, and shebang executables
- current-working-directory assumptions, symlinks, writable parent directories, temp files, generated env files, artifacts, CI variables, and secret-provider output

Record each interpreter or code-loading occurrence in `dangerous-capabilities.jsonl`.

## Trust-Boundary Analysis

For every sourced file, resolve:

- the effective path after current-directory changes, variables, globbing, and symlink resolution
- file and parent-directory owners, modes, ACLs, mounts, and replacement/rename permissions
- who creates or updates it: developer, deploy user, CI job, artifact download, secret writer, container mount, or lower-privileged service
- whether untrusted values are written into it without literal encoding
- the privilege, credentials, network reach, and deployment authority of the sourcing process

Example execution:

```sh
# deploy.sh
. ./.env
```

```sh
# .env controlled through CI or a writable deployment directory
DRADIS_KAFKA_PASSWORD=$(id > /tmp/proof)
```

The command substitution executes while sourcing. Classify it as confirmed conditional code execution when a lower-trust actor can create, modify, replace, or redirect the sourced file. Severity follows the sourcing process's privileges and reachable assets.

If the file and every writable path component are controlled by the same trusted principal as the script, record the ownership evidence and consider `negative_closed` or an engineering hardening note. If provenance, permissions, CI generation, runtime mounts, or symlink behavior cannot be established, keep `candidate` or `coverage_debt`; do not silently dismiss it as "local only."

## Minimal Fixes

- use the deployment platform's native environment injection or env-file support when it parses values as data
- use a dotenv parser that accepts a fixed `KEY=VALUE` grammar and never invokes a shell
- allowlist keys, reject malformed lines and duplicates, preserve values literally, and export them through a data API
- use fixed absolute paths and strict ownership/mode checks as defense in depth when migration cannot happen immediately

Do not replace `source` with `eval`, `xargs`, command substitution, or another path that reparses values as shell syntax.

## Search Starters

```bash
rg -n --glob '*.{sh,bash,zsh,ksh}' '^\s*(source\s+|\.\s+)|\beval\b|\b(bash|sh|zsh|ksh)\s+-c\b'
rg -n --glob 'Makefile*' --glob 'Procfile*' --glob 'Dockerfile*' --glob '*.{yml,yaml,service}' 'source\s+|(^|[;&|])\s*\.\s+[^.]|\b(bash|sh)\s+-c\b'
rg -n '\.env|env_file|EnvironmentFile|Exec(Start|Stop)|entrypoint|command:' .
```
