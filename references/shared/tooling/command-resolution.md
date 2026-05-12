# Command Resolution Standard

Use this standard before invoking optional external audit tools, repository-defined scanner scripts, ecosystem package-manager audit commands, IaC scanners, secret scanners, smart-contract tools, SBOM tools, or CI-provided scanner wrappers.

The goal is to reduce hallucinated commands while staying version-aware. Command references are candidates, not fixed truth.

---

## When To Apply

Apply command resolution for commands whose availability, name, subcommands, or flags may vary by environment or version, including:
- dependency and SCA tools such as `composer audit`, `pip-audit`, `npm audit`, `pnpm audit`, `yarn npm audit`, `govulncheck`, `cargo audit`
- secret scanners such as `gitleaks` or `trufflehog`
- IaC, container, and cloud scanners such as `trivy`, `checkov`, `tfsec`, `terraform`, `helm`, or `kubectl`
- smart-contract tools such as `forge`, `hardhat`, `slither`, or `mythril`
- language security tools such as `semgrep`, `bandit`, `brakeman`, `gosec`, or ESLint security plugins
- project scripts such as `make audit`, `npm run security`, `composer audit`, CI jobs, or internal scanner wrappers

Basic read-only enumeration commands such as `rg`, `git status`, `git diff`, `git log`, `find`, and `ls` do not need full command resolution. If they are unavailable, use a normal fallback and record only material limitations.

---

## Resolution Order

1. Prefer the repo-configured scanner path when present.
   - Inspect scripts before running them.
   - Examples: `package.json` scripts, Composer scripts, Makefile targets, Gradle tasks, CI workflows, preconfigured SCA files, smart-contract framework scripts.
2. Verify that the configured command is safe enough for the audit context.
   - Do not run destructive, trust-changing, network-heavy, credential-exfiltrating, or remote-code bootstrap commands without explicit approval and a clear reason.
   - Treat `curl | sh`, broad install scripts, production deploy steps, and cleanup/reset targets as unsafe by default.
3. If no suitable repo-configured path exists, use the ecosystem or domain module's candidate command list.
4. Probe the candidate binary before executing the scanner.
   - Use `command -v <binary>` or the platform equivalent.
   - Capture version when available.
   - Read help from the actual installed tool before choosing flags.
5. Prefer help in this order:
   - `<binary> <subcommand> --help`
   - `<binary> <subcommand> -h`
   - `<binary> --help`
   - `<binary> -h`
   - project docs or CI usage for that exact installed tool
6. Build the final command from observed help and repo context.
7. Record the invocation, result, and limitations in audit state.

Never invent adjacent command names such as `phpaudit` when only `php-audit`, `composer audit`, or another documented candidate is known.

---

## Candidate Command Rules

Ecosystem and domain files may list:
- known binaries
- preferred probes
- common subcommands
- common flags
- repo signals that make a tool relevant

They must not imply that a stale exact command is always valid.

Use current tool help, repo scripts, and local availability to decide the final command.

---

## Fallbacks And Limitations

If a tool is missing, help cannot confirm the needed flags, or execution is blocked:
- do not fabricate a replacement command
- record the blocker
- fall back to manual manifest, lock-file, IaC, config, or source review when feasible
- include the limitation in coverage debt or report notes when it affects confidence

Example:

```text
Dependency audit not executed: `composer` is present but `composer audit --help` does not show the audit subcommand. Fallback reviewed `composer.lock` and framework versions manually.
```

---

## State Shape

Record material tool decisions under `tool_invocations` in audit state.

Prefer:

```json
{
  "tool_invocations": [
    {
      "surface": "dependencies",
      "ecosystem": "php",
      "candidate": "composer audit --locked",
      "candidate_source": "references/shared/dependencies/php.md",
      "resolution_source": "repo-configured|ecosystem-default|manual",
      "probe_commands": ["command -v composer", "composer audit --help"],
      "tool_version": "Composer 2.x",
      "help_result": "supported",
      "executed_command": "composer audit --locked",
      "exit_code": 0,
      "status": "executed",
      "limitations": []
    }
  ]
}
```

Recommended `status` values:
- `executed`
- `unavailable`
- `unsupported`
- `blocked`
- `skipped_unsafe`
- `manual_fallback`

Do not store large raw scanner output in audit state. Store normalized findings in the report and keep only compact command evidence in state.

---

## Reporting Expectations

Reports should mention external tools only when material:
- scanner command executed
- scanner was expected but unavailable
- repo-configured command was skipped as unsafe
- manual fallback affects dependency, IaC, secret, smart-contract, or SCA confidence

Tool output alone is not a confirmed finding. Tie every scanner result back to the current repo state, manifest, config, code path, image, or deployment surface.
