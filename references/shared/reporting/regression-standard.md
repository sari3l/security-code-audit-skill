# 回归复测标准

Use this standard when mode is `regression`.

## Purpose

Regression mode is for remediation verification, not broad vulnerability discovery.

It answers:
- which findings from the latest report are fixed
- which findings are still present
- which findings are only partially fixed
- which findings could not be retested reliably
- how the current deployment or integration context changed the real attack preconditions for those findings when that context is material

## Baseline Selection

- read the most recent usable standardized report from the running directory's `output/` subdirectory, choosing by parsed filename timestamp first
- use that report as the only required retest baseline
- do not merge multiple older reports into one retest target set unless the user explicitly asks

Preferred recency order:
- parse the timestamp immediately after the `security-code-audit-` filename prefix in the format `YYYY-MM-DD-HHMMSS`
- only treat files matching the current standard filename shape `security-code-audit-{YYYY-MM-DD-HHMMSS}-{mode}-{short-hash}.md` in `output/` as usable regression baselines
- ignore older alternate filename shapes instead of trying to normalize them into the new flow
- if multiple reports share the same timestamp, prefer the newest file mtime
- treat placeholder times as invalid if they were not generated from the real wall-clock time for that report
- if filename timestamp and report `Date` metadata disagree materially, prefer the value backed by the real captured timestamp or file mtime
- if parsing fails or the name is non-standard, ignore that file as a regression baseline
- if metadata is missing or malformed on an otherwise-standard file, fall back to file mtime

If no usable baseline report exists:
- print a concise note
- stop the run
- do not perform a fallback broad scan

Legacy state note:
- older code-audit runs may have a usable baseline report in `output/` while
  intermediate records live in `.security-code-audit-state/`
- detect that split layout and record `legacy_split_state_detected`
- the baseline report in `output/` remains the regression source of truth; do
  not skip it just because legacy hidden-directory state is absent, stale, or
  structurally incompatible
- legacy state may provide optional untrusted hints only after fresh current
  recon and freshness classification
- the regression run must not write `.security-code-audit-state/`; write new
  retest state under the standardized `output/security-code-audit-...-state/`
  bundle

## Retest Target Selection

Extract from the latest report:
- finding id or title
- category
- fingerprint
- affected routes, resources, or sinks
- prior attack vector
- prior minimal fix expectation
- prior deployment, exposure, auth-owner, or network assumptions when they were stated or can be inferred from the prior attack vector

If the latest report has no usable findings, stop with a concise note.

## Retest Statuses

- `Fixed`
  The prior exploit path is no longer credible and the vulnerable control is materially repaired.

- `Still Present`
  The prior exploit path still works or the same control gap remains.

- `Partially Fixed`
  Some locations or paths were repaired, but the vulnerability remains materially exploitable somewhere in scope.

- `Unable To Verify`
  Reliable retest is blocked by missing code, missing environment, or insufficient evidence.

## Retest Rules

- use the prior fingerprint first, then route/resource family, then prior exploit path
- validate the current code directly; do not trust the prior report as proof
- reopen the current deployment or integration path when exploitability depends on a host app, reverse proxy, mount prefix, service mesh, or internal-only network placement
- if a finding moved but the exploit path is still materially the same, keep it tied to the same baseline finding
- if the fix changed the code shape but left equivalent exposure, classify as `Still Present` or `Partially Fixed`, not `Fixed`
- do not classify a finding as `Fixed` solely because an external control reduced exposure; if the code weakness remains, keep the retest status grounded in the current code and record the lower real-world attack preconditions separately
- when deployment or integration context materially lowers actual risk without removing the underlying weakness, explain both the reduced exposure and the remaining residual risk
- do not create a new broad finding list for unrelated surfaces during regression mode

## 输出要求

终端摘要使用中文，并包含：
- 使用的基线报告
- `已修复` 数量
- `仍存在` 数量
- `部分修复` 数量
- `无法验证` 数量
- 当部署或集成变化实质改变一个或多个复测项的暴露面时，给出简洁的上下文漂移说明

历史文件使用中文，并包含：
- 基线报告元信息
- 基线报告时间
- 每个既往漏洞对应一个复测条目
- 每个复测状态的简洁理由
- 复测置信度受限时的明确阻塞项
- 当当前暴露面或集成上下文实质改变真实攻击前置条件时，写明该上下文

## 最小复测条目格式

```markdown
### [RETEST]-[NNN]: [Prior Finding Title]
- **基线报告**: [file]
- **基线时间**: [YYYY-MM-DD HH:MM:SS TZ]
- **指纹**: [稳定漏洞指纹]
- **既往严重性**: 严重 / 高 / 中 / 低 / 信息
- **复测状态**: 已修复 / 仍存在 / 部分修复 / 无法验证
- **当前位置**: `file/path.ext:line` 或 `N/A`
- **当前暴露上下文**: [public, internal-only, host-app-auth, reverse-proxy-restricted，或其他相关上下文]
- **复测说明**: [什么改变了，什么仍然成立]
- **上下文漂移**: [部署或集成如何改变实际风险或攻击前置条件；相关时填写]
- **证据**:
  ```[lang]
  // 当前相关代码或配置
  ```
- **残余风险**: [仅在仍存在或部分修复时填写]
```
