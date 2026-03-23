# Markdown Security Review

Markdown is often treated like harmless text, but real systems render it into HTML, fetch remote resources, store it for later display, or feed it into LLM context. Review the renderer, sanitizer, embeds, and trust boundary rather than the syntax alone.

---

## What To Enumerate First

1. every markdown renderer, parser, and sanitizer in the stack
2. whether raw HTML is preserved, stripped, or sanitized after render
3. where markdown appears: comments, tickets, docs, chat, wikis, imported files, email templates, changelogs
4. whether rendered markdown supports images, links, iframes, mermaid, math, includes, or custom extensions
5. whether markdown content is later used as retrieval or prompt context for AI features

---

## High-Risk Patterns

- markdown rendered to HTML without a strong sanitizer
- raw HTML enabled by default or re-enabled for "trusted users"
- dangerous URL schemes such as `javascript:` or `data:` in links or embeds
- SVG or HTML attachments accepted and later rendered inline
- remote image or embed fetching that leaks internal metadata, auth headers, or viewer identity
- markdown transformed twice, where the first pass encodes and the second pass decodes or re-renders it
- custom markdown extensions that inject HTML, script-like widgets, or server-side includes
- markdown content treated as trusted instructions for tools, agents, or operators

---

## Audit Questions

- Which library renders markdown, and does it allow raw HTML?
- Is sanitization applied before render, after render, or not at all?
- Are links normalized and scheme-checked?
- Can images, embeds, or includes cause outbound requests or preview fetches?
- Is user markdown stored and later shown to admins or cross-tenant viewers?
- Is markdown ever copied into prompts, summaries, retrieval results, or skill context?

---

## Grep Starting Points

```bash
rg -n "markdown|marked|remark|rehype|showdown|commonmark|blackfriday|goldmark|mistune|markdown-it|renderMarkdown|mdx" .
rg -n "sanitize|DOMPurify|bleach|allowHtml|unsafeHtml|raw HTML|rehype-raw|html: true" .
rg -n "javascript:|data:text/html|iframe|img src|mermaid|mathjax|katex|embed|include" .
rg -n "README|CHANGELOG|docs|wiki|comment|issue body|description" .
```

---

## Review Strategy

1. Confirm where markdown enters the system and who can author it.
2. Trace markdown through render, sanitize, cache, and display paths.
3. Test whether links, images, SVG, and raw HTML survive each stage.
4. Check whether markdown is reused outside browser rendering, especially in prompt or retrieval pipelines.

---

## Related References

- `references/application/vulnerabilities/xss.md`
- `references/application/vulnerabilities/ssrf.md`
- `references/application/vulnerabilities/prompt-injection.md`
- `references/shared/artifacts/skill-files.md`
