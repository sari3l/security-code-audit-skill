# security-code-audit

当前版本：`v1.1.0`

面向 Web/API、后端、全栈、智能合约，以及 artifact-centric 仓库的代码安全审计 skill。

`security-code-audit` 适合代码安全审计、SAST 风格分析、OWASP 风格检查、依赖审计、智能合约审计、artifact 与 prompt 面审计，以及修复回归验证。重点是基于真实代码、真实攻击面、bounded tracing、持久化 audit state 和高信号报告，而不是只做浅层模式匹配。

English documentation: [README.md](README.md)

## 1. 使用方式

- `/security-code-audit`
  默认完整审计。等价于 `standard single`。
- `/security-code-audit quick`
  快速高风险初筛。
- `/security-code-audit deep`
  深度审计，覆盖更强，攻击链和验证更深。
- `/security-code-audit regression`
  以最近一份报告为基线做修复回归验证。
- `/security-code-audit help`
  显示参数、模式、执行方式和示例。

参数：
- 深度：`quick` | `standard` | `deep` | `regression`
- 执行模式：`single` | `multi`
- `multi` 是 beta；如果宿主不支持 delegation，会自动回退到 `single`

示例：
- `/security-code-audit deep multi`
- `/security-code-audit regression`
- `/security-code-audit deep --agents=multi`

## 2. 核心能力

- 按目标面路由
  RECON 后先选择 target profile，再根据实际 surface 路由到主知识域和共享模块。
- 基于真实代码和证据
  finding 需要落到真实文件、真实利用路径和可执行的最小修复建议。
- bounded tracing
  双向 tracing 会把 source-to-sink 和 state-transition 分析收敛到真实信任边界，而不是无限制扩图。
- 枚举重复问题
  不只报第一个命中点，而是尽量找全同类高价值位置。
- audit state 连续性
  `.security-code-audit-state/` 保存紧凑 run context、code fact snapshot、evidence observation、loaded-module 决策、function-chain 记录和 invalidation，帮助每次运行快速重新对齐上下文。
- 覆盖依赖和 artifact 面
  代码、依赖、markdown、prompt、API spec、notebook、配置和 IaC 都能进入同一套审计流程。
- 覆盖债务可见
  对于 partial、blocked、invalidated 的审计面，会显式记录成 coverage debt，而不是假装已经扫完。
- 证据分层
  主 findings 只保留已确认问题，高信号但未证实的内容会进入 candidate signals 或 working hypotheses，而不是被静默丢掉。
- Shape hint 与 evidence gate
  reference 模块现在包含针对常见应用与智能合约问题的简洁风险形状示例。这些示例只用于启发调查，不是签名；每个 finding 仍需证明攻击者影响、可达的失效边界或不变量、补偿控制缺失，以及具体影响。
- 2025 incident pattern 覆盖
  智能合约方法论现在覆盖 DeFi/DEX/lending/bridge、upgradeable、signer、frontend transaction builder、relayer、admin 和 supply-chain 路径，只要它们能影响链上资产、权限、签名或升级。
- 历史与回归支持
  `.security-code-audit-reports/` 保存人类可读报告，`regression` 可基于最近报告做回归验证，并配合当前扫描结果做历史比对。
- 可选多 agent
  `multi` 可在大仓库里扩覆盖，但仍保持单一报告出口。

## 3. 架构

运行时架构：分阶段扫描、mode policy、执行拓扑、state freshness 检查、按目标画像路由、advisory code facts、evidence observation routing、按需加载，并通过 bounded tracing 和持久化 state 保持一致性。

```mermaid
flowchart TD
    A["用户命令<br/>/security-code-audit [mode] [execution]"]
    B["SKILL.md<br/>入口路由 + 共享工作流"]
    MP["Mode policy<br/>quick | standard | deep | regression<br/>scope、depth、stop conditions"]
    C["启动控制面<br/>解析 mode 和 execution<br/>加载 core、execution、mode rules"]
    X["执行拓扑<br/>single | multi<br/>ownership、sharding、worker contract、merge"]

    ST[".security-code-audit-state<br/>机器可读 continuity state"]
    SR["State reader<br/>freshness、invalidation、<br/>continuation、merge hints<br/>不是安全证明"]

    D["Recon 阶段<br/>识别仓库结构、技术栈、artifacts、<br/>claims、risk areas 和 state freshness"]
    RUI["core/untrusted-repo-input.md<br/>repo docs、comments、old reports<br/>和 claims 只作为 hints"]
    PC["core/project-context.md<br/>verified claims、business invariants、<br/>trust-boundary assumptions、<br/>deployment assumptions、change themes"]
    CF["core/surface-profile.md<br/>surface profile + state indexes<br/>entrypoints、routes、sinks、<br/>state transitions、artifacts、limitations"]
    CB["Audit context bundle<br/>observed surfaces、business assets、<br/>invariants、trust boundaries、<br/>code facts、limitations、invalidations"]

    E["目标画像选择<br/>application | smart-contract | artifact-centric"]
    F["core/loading.md<br/>懒加载 + 按需路由"]
    G["主知识域<br/>application | smart-contract"]
    H["共享模块<br/>artifacts、dependencies、tooling、<br/>reporting、state 标准"]
    T["核心质量控制<br/>integrity、coverage、findings、<br/>severity、fingerprints、tracing"]
    Q["core/deep-semantic-controls.md<br/>deep、multi 或复杂高风险 surface"]
    U["可选辅助工具链<br/>command-resolution.md<br/>scanner evidence 与 command context，<br/>不是审计主干"]

    I["Hypothesis-driven 审计阶段<br/>generate、validate、falsify、bound<br/>当前代码发现深度由 mode 控制"]
    EO["Evidence observation envelope<br/>raw observations、tool output、<br/>blockers、negative evidence、<br/>schema gaps、custom signals"]
    J["证据收敛与整理<br/>路由 observations、验证 findings、去重，<br/>收敛 coverage、tools、gates、obligations"]
    HM["Historical miss gate<br/>先用当前代码重开历史 findings，<br/>再做生命周期标签判断"]
    K["报告与回归<br/>输出 findings、对比历史、验证修复"]

    R[".security-code-audit-reports<br/>人类可读 findings 和历史报告"]

    A --> B
    B --> MP
    B --> C
    C --> X
    ST -. read .-> SR
    SR -. freshness 与 invalidation .-> D
    SR -. continuation 与 open obligations .-> CB
    SR -. merge ledgers 与 coverage state .-> J
    MP --> D
    X --> D
    RUI --> D
    D --> PC
    D --> CF
    PC --> CB
    CF --> CB
    CB --> E
    E --> F
    F --> G
    F --> H
    F --> T
    F --> Q
    H --> U
    MP --> I
    X --> I
    G --> I
    H --> I
    T --> I
    Q -. conditional semantic controls .-> I
    U -. 可选 scanner 证据 .-> I
    U -. tool-output observations 与 blockers .-> EO
    I --> EO
    EO --> J
    J --> HM
    HM --> K
    K --> R
    X -. persist topology 与 merge inputs .-> ST
    D -. persist run context .-> ST
    PC -. persist project context .-> ST
    CF -. persist code facts 与 limitations .-> ST
    F -. persist selected modules .-> ST
    U -. persist command probes 与 blockers .-> ST
    EO -. preserve observations before routing .-> ST
    I -. update traces、tools、gates、coverage .-> ST
    J -. persist hypotheses、obligations、invalidations .-> ST
    HM -. persist historical misses 或 lifecycle allowance .-> ST
    R -. regression input only .-> K
```

`State reader` 是概念性操作：读取 prior state，总结 freshness / invalidation、continuation / open obligations 和 coverage / merge hints，然后在不把这些 hints 当作安全证明的前提下使用它们。它不是新的运行时文件、schema、服务或平台组件。

这套 skill 按层拆分：

| 路径 | 作用 |
| --- | --- |
| `SKILL.md` | 主路由、help path、共享流程和进度规则 |
| `core/` | integrity、coverage、findings、severity、project context、懒加载、surface profile、advisory code facts、bidirectional tracing 和 deep semantic 控制 |
| `execution/` | single-agent 和 beta multi-agent 执行拓扑、worker contract、sharding 与 merge 规则 |
| `profiles/` | RECON 后的目标语义：`application`、`smart-contract`、`artifact-centric` |
| `references/application/` | Web/API/后端审计主知识域 |
| `references/smart-contract/` | 智能合约与链上逻辑审计主知识域 |
| `references/shared/` | artifact、dependency、tooling、reporting 和 audit-state 的共享标准 |
| `modes/` | `quick`、`standard`、`deep`、`regression` 的深度契约 |

输出层：

| 路径 | 作用 |
| --- | --- |
| `.security-code-audit-reports/` | 人类可读 findings、历史、回归基线和 action items |
| `.security-code-audit-state/` | 机器可读 run context、surface inventory、project context、code fact snapshot、evidence observation、tool invocation 记录、deep gate ledger、function chain、hypothesis 和 invalidation，适用于每次运行 |
