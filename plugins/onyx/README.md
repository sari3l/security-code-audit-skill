# Onyx Code Audit Plugin

这个插件让 `security-code-audit` 在理解架构和代码变更之后，通过 Onyx 查找相关需求，再进入安全语义审查。

## 最短配置

仓库不会保存组织内部的 Onyx 地址。内置 `config.json` 只有禁用的 `https://onyx.example.com/mcp` 示例值，因此使用前必须创建用户配置：

```text
~/.config/security-code-audit/plugins/onyx.json
```

```json
{
  "url": "https://your-onyx-host.example/mcp",
  "enabled": true
}
```

在启动 Codex 的同一个 shell 中设置配置路径和 token：

```bash
export ONYX_AUDIT_CONFIG="$HOME/.config/security-code-audit/plugins/onyx.json"
export ONYX_AUDIT_TOKEN='<current Onyx PAT>'
codex
```

然后在新线程中先验证连接器：

```text
检查 Onyx requirements connector 是否已配置。只调用 discover_requirement_connectors，只报告 endpoint、enabled、auth.configured、operations 和错误状态，不输出凭据。
```

确认 endpoint 是用户配置的地址、`enabled: true` 且 `auth.configured: true` 后，在待审计项目中运行：

```text
/security-code-audit deep
```

审计会自动在正确阶段使用 Onyx。首次调用工具时，Codex 可能要求你批准 MCP 操作。

## 安装

这个 Onyx 插件是 `security-code-audit` 自己的插件。首次使用该仓库的 marketplace 时，在 `security-code-audit` 目录执行：

```bash
codex plugin marketplace add "$PWD"
codex plugin add onyx@personal
```

如果 `codex plugin list` 已显示 `onyx@personal` 为 `installed, enabled`，不需要重复安装。安装或升级插件后请新开 Codex 线程，让新的 MCP tools 和 Skill 生效。

## 用户配置

建议把用户配置保存在：

```text
~/.config/security-code-audit/plugins/onyx.json
```

文件必须提供真实 `url` 并启用连接器：

```json
{
  "url": "https://your-onyx-host.example/mcp",
  "enabled": true
}
```

然后在启动 Codex 前设置配置路径和 token：

```bash
export ONYX_AUDIT_CONFIG="$HOME/.config/security-code-audit/plugins/onyx.json"
export ONYX_AUDIT_TOKEN='<current Onyx PAT>'
codex
```

`ONYX_AUDIT_CONFIG` 展开后必须是绝对路径，并指向存在的普通 JSON 文件。插件会把用户 JSON 合并到内置安全默认值中。修改这个 JSON 不需要编辑安装缓存，也不需要重新安装插件；修改 `ONYX_AUDIT_CONFIG` 或 token 环境变量后，需要从对应 shell 重启 Codex。

不要编辑 Codex 安装缓存中的 `config.json`，也不要依赖修改插件源码保存个人配置。缓存会被重装覆盖，源码修改还需要刷新插件版本。

## 可配置字段

用户 JSON 可以声明以下字段：

| 字段 | 用途 |
|---|---|
| `url` | HTTPS Streamable HTTP MCP endpoint |
| `searchTool` | 远端搜索工具名 |
| `fetchTool` | 可选的远端单文档读取工具名 |
| `arguments` | 稳定参数到远端参数名的映射；值为 `null` 时不发送该参数 |
| `staticArguments` | 发送给 search/fetch 的安全声明式固定参数 |
| `enabled` | 是否启用连接器 |

`configEnv` 和 `tokenEnv` 是插件与 Codex host 之间的固定转发契约，用户 JSON 不能改变；本插件分别固定为 `ONYX_AUDIT_CONFIG` 和 `ONYX_AUDIT_TOKEN`。

完整字段约束见 [`config.schema.json`](./config.schema.json)。用户配置会经过与内置配置相同的安全校验：只允许 HTTPS，不允许 URL 凭据、URL fragment、凭据型 query 参数、内联 secret、可执行命令或脚本字段。

仓库中的安全占位配置使用：

```json
{
  "url": "https://onyx.example.com/mcp",
  "tokenEnv": "ONYX_AUDIT_TOKEN",
  "searchTool": "search_indexed_documents",
  "arguments": {
    "limit": null
  },
  "staticArguments": {
    "search": {
      "skip_query_expansion": true
    }
  },
  "enabled": false
}
```

Onyx 的 `search_indexed_documents` 接受 `query`，但不接受 `limit`，因此 `limit: null` 会显式省略这个参数。适配器已经根据架构和代码变更扩展查询锚点，所以默认关闭 Onyx query expansion，并最多顺序执行四个优先查询。示例 endpoint 默认禁用，只有用户 JSON 中的 `enabled: true` 会启用远端查询。

当前连接器是 search-only。索引搜索结果已经包含选中的文档片段，而 `open_urls` 不能读取内部索引文档，因此没有把它错误配置成 `fetchTool`。

## 状态和排障

| 状态 | 含义 | 处理 |
|---|---|---|
| `configured` | 配置可读取并通过校验 | 再检查 `auth.configured` 和 endpoint |
| `missing_auth` | MCP 进程没有收到 token；本次跳过 Git 锚点、search、fetch 和 render，不连接 Onyx | 在启动 Codex 前设置 token，然后重启 Codex |
| `invalid_connector` | 默认配置或用户 JSON 无效 | 查看错误；优先检查绝对路径、JSON、HTTPS URL 和字段名 |
| `missing_tool` | 远端没有声明配置的工具 | 核对 `searchTool`/`fetchTool` 与 Onyx 实际工具名 |
| `timeout` | 连接或全部查询超时 | 检查网络和 Onyx 服务状态后重试 |
| `partial` | 已取得部分文档，但至少一个查询失败 | 使用已有需求上下文继续，并在报告中保留失败状态 |
| `no_match` | 调用成功但没有相关文档 | 不能据此断言“没有需求” |

最常见的问题是先启动 Codex、后设置环境变量。已经运行的 Codex/MCP 进程不会自动继承父 shell 后来新增的变量。

## 查询锚点

插件不会只靠 commit title。它在架构和当前变更 recon 之后，按优先级使用：

1. Code Audit 从审计范围、宿主元数据和 Git 历史中自动发现的 MR/PR 引用，以及 ticket、RFC、Issue 或文档 ID
2. route、API、class、function、contract、data entity 和 configuration key
3. service、component、actor、role、business flow、invariant 和 trust boundary
4. branch、commit subject/body 和 changed path

用户只需发起 Code Audit，不需要为 Onyx 另外输入 MR。若审计范围、宿主元数据、本地 MR refs、branch 或 commit 中已出现下面任一形式，它们会自动归一为同一个 MR：

```text
https://gitlab.example.com/group/project/-/merge_requests/1412
project/merge_requests/1412
merge_requests/1412
project MR1412
MR1412
!1412
```

当引用没有项目名时，优先使用 Git `origin` 的项目名，再使用目标仓库目录名补全。插件会保留原始引用查询，同时优先生成 `project MR1412 requirement_skills.md`、`project MR1412 design_skills.md` 和 `project MR1412`。返回结果必须在 URL 路径中同时匹配项目和 MR IID 才能获得精确 MR 关联；同一项目的其他 MR 会被降为低置信度编号碰撞。

如果 recon 没有发现 MR/PR 编号，插件不会要求用户补充，而是优先查询 `project + HEAD commit + requirement_skills.md`、`project + HEAD commit + design_skills.md`、完整 HEAD commit 和 source branch，让 Onyx 反查对应变更；再使用 ticket ID、代码语义和架构语义补充关联。commit 或 branch 命中仍需结合 repository、文档内容和当前代码验证，不能单独证明需求归属。

锚点不包含完整 diff 或源代码。需求文档始终按不可信外部上下文处理，必须回到当前代码验证。

## 安全边界

- token 只从 `.mcp.json` 明确转发的环境变量读取。
- token 不得写入 JSON、聊天、MCP 参数、Web UI、audit state、日志或报告。
- 远端结果或错误如果回显当前 token，会在进入模型和 Web UI 前脱敏。
- 只读取已安装 Onyx 插件的 manifest、默认配置，以及 `ONYX_AUDIT_CONFIG` 明确指定的用户 JSON。
- 不从被审计仓库发现或执行插件、connector、命令或脚本。
- Onyx 不可用不会缩小代码审计范围；插件记录准确状态后继续审计。

## 开发验证

```bash
cd plugins/onyx
npm ci
npm test
npm audit --omit=dev
```

`npm test` 会重建 `server/bundle.mjs`。安装后的插件运行该 bundle，不依赖 `node_modules`。
