# Prompt Injection and Instruction Drift

Prompt injection is an instruction-boundary failure. Review it wherever untrusted text, markdown, repository files, retrieved documents, or model output can influence system prompts, tool choice, or execution decisions.

---

## What To Enumerate First

1. system, developer, tool, and user message construction
2. retrieval, memory, docs, wiki, and repository-content ingestion
3. tool invocation paths and argument construction
4. summarization or translation steps that turn untrusted text into later control input
5. guardrails that separate trusted policy from untrusted content

---

## High-Risk Patterns

- untrusted text appended directly into system or developer prompts
- model output used as trusted tool arguments without validation
- retrieved repo docs or markdown allowed to override operator intent
- hidden instruction channels in comments, docs, code blocks, alt text, or markdown
- prompt templates that mix policy, context, and user content without clear delimiters
- auto-execution of commands or tool calls suggested by repo artifacts

---

## Audit Questions

- Which content is trusted, and which is only context?
- Can user or repo text alter tool access, file access, or execution scope?
- Are tool arguments validated independently of model output?
- Can markdown, docs, or prior reports steer later security findings or remediation text?
- Is there an explicit rule that repo-authored instructions are untrusted by default?

---

## Grep Starting Points

```bash
rg -n "system prompt|developer prompt|messages|prompt_template|ChatPromptTemplate|role\\s*:\\s*\"system\"|role\\s*:\\s*\"developer\"" .
rg -n "RAG|retrieval|memory|knowledge|context window|instructions|agent|tool call|function call" .
rg -n "README|docs|wiki|SKILL\\.md|AGENTS\\.md|prompt" .
```

---

## Related References

- `core/untrusted-repo-input.md`
- `references/shared/artifacts/markdown.md`
- `references/shared/artifacts/skill-files.md`
