# Skill and Prompt File Review

Instruction-bearing files deserve first-class review. `SKILL.md`, `AGENTS.md`, prompt templates, tool wrappers, and similar assets can create prompt injection, capability overreach, trust-boundary drift, or hidden execution paths even when the surrounding code is otherwise clean.

---

## What To Enumerate First

1. `SKILL.md`, `AGENTS.md`, prompt templates, system/developer prompt files, tool manifests, and command wrappers
2. places where repo-authored text is loaded into agent context or used as trusted instruction input
3. user-controlled content copied into system prompts, tool arguments, or routing decisions
4. permissions, tool access, file access, and network assumptions encoded in prompt or agent config
5. any retrieval layer that mixes trusted instructions with untrusted repo content

---

## High-Risk Patterns

- repo-authored instructions treated as higher priority than platform or operator controls
- prompt templates concatenating untrusted user input directly into system or developer messages
- tool calls formed from retrieved markdown, issue text, or README content without trust separation
- agent roles with broad filesystem, network, or credential access but no task scoping
- hidden prompt files containing secrets, tokens, internal endpoints, or operational credentials
- "follow repository instructions" logic without filtering for untrusted content
- automated execution paths triggered by docs, examples, or retrieved artifacts
- safety policy split across many files with unclear precedence

---

## Audit Questions

- What instruction sources exist, and what is their intended precedence?
- Can user or repo content influence system prompts, tool selection, or execution permissions?
- Are untrusted docs clearly separated from trusted operator policy?
- Do tool wrappers validate arguments independently of prompt instructions?
- Are secrets, internal URLs, or credentials embedded in prompts or examples?
- Can a malicious markdown/doc file steer later scans, summaries, or remediation output?

---

## Grep Starting Points

```bash
rg -n "SKILL\\.md|AGENTS\\.md|prompt|system message|developer message|tool call|function call|retrieval|RAG|agent" .
rg -n "messages\\s*=|role\\s*:\\s*\"system\"|role\\s*:\\s*\"developer\"|system_prompt|prompt_template|ChatPromptTemplate" .
rg -n "README|docs|wiki|knowledge base|memory|instruction|policy" .
rg -n "exec|shell|tool|function|run command|browse|filesystem|network" .
```

---

## Review Strategy

1. Build a precedence map: platform rules, operator rules, repo files, retrieved text, and user input.
2. Mark every untrusted-to-trusted boundary where text becomes instruction or tool arguments.
3. Check whether tool permissioning and argument validation still hold when prompts are malicious.
4. Report prompt injection, instruction drift, and secret-bearing prompt artifacts separately from ordinary XSS or markdown rendering bugs.

---

## Related References

- `core/untrusted-repo-input.md`
- `references/application/vulnerabilities/prompt-injection.md`
- `references/shared/artifacts/markdown.md`
