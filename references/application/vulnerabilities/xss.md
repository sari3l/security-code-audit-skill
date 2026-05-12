# Cross-Site Scripting (XSS)

XSS happens when untrusted data reaches a browser execution context without the correct context-aware encoding or sanitization.

Core classes:
- reflected XSS
- stored XSS
- DOM-based XSS

---

## Output Contexts To Classify

- HTML body
- HTML attribute
- JavaScript string or script block
- URL / protocol attribute
- CSS or style attribute
- DOM sink such as `innerHTML`, `document.write`, or `dangerouslySetInnerHTML`

The context matters more than the input source.

---

## What To Enumerate First

1. all templates and view files
2. all raw HTML rendering helpers and sanitization bypasses
3. all client-side DOM sinks and URL-to-DOM flows
4. stored user content fields: comments, profiles, tickets, markdown, rich text

---

## High-Risk Patterns

- raw output helpers such as `|safe`, `html_safe`, `Html.Raw`, `{!! !!}`, triple-stash
- DOM sinks fed from `location`, `document.referrer`, `postMessage`, or API responses
- markdown or rich-text sanitizers that preserve dangerous tags or attributes
- sanitized or escaped content later decoded, rewrapped, or reparsed into a more dangerous browser context
- URL, HTML entity, or template decoding happens after the apparent escaping step
- file upload flows serving back SVG or HTML

---

## Commonly Missed Cases

- values safe in HTML body but unsafe inside scripts or attributes
- admin-only stored XSS where normal users can submit content that staff later views
- sanitized HTML later re-wrapped as trusted again
- CSP present but incomplete, leading to false confidence
- markdown-to-HTML-to-DOM pipelines where each stage assumes the previous stage already made the content safe
- browser canonicalization of URLs, protocols, or entities changes the final execution context after validation

---

## Root-Cause Lens

Do not define XSS by a favorite tag or event-handler payload.

Define it by the semantic failure:
- untrusted data crosses into a browser-executable context
- context changes across template rendering, markdown conversion, sanitization, DOM insertion, or client-side decoding
- one layer escapes for one grammar while a later layer reparses under a different grammar

This means review should focus on:
- the final browser sink and exact context it sees
- every decoding, sanitization, rendering, and DOM transformation step before that sink
- whether trusted HTML wrappers or client frameworks reclassify previously untrusted content

The payload is only the probe.
The root cause is browser-context interpretation drift.

---

## Dangerous Patterns

```javascript
element.innerHTML = userInput
```

```erb
<%= raw comment.body %>
```

```php
{!! $comment->body !!}
```

---

## Safe Patterns

- auto-escaping templates by default
- context-aware encoding for HTML, JS, URL, and CSS separately
- narrow sanitization for explicitly supported HTML subsets
- avoiding raw DOM HTML sinks unless the content is already sanitized and trusted

---

## Audit Questions

- Where does the canary land exactly in the final HTML or DOM?
- Is the escaping correct for that specific context?
- Can the content be stored and replayed to another user or role?
- Which rendering or decoding stages transform the content before the final sink?
- Does any step sanitize for one context and then reparse the result in another context?
- Do front-end frameworks unwrap trusted HTML later in the flow?

---

## Deep Semantic Gate

In `deep` mode, create an `xss_browser_context` gate for each rendering pipeline, rich-text/markdown surface, template family, DOM sink group, or file-preview path that can place attacker-controlled content in a browser.

The gate is not `covered` until the audit records:
- source-to-sink lifecycle for reflected, stored, DOM, markdown/rich-text, uploaded-file, and admin-viewed content
- final browser context for each sink: HTML body, attribute, script string, URL/protocol, CSS/style, raw DOM HTML, iframe/document, SVG/HTML/PDF preview, or framework hydration boundary
- dependency semantics for template autoescaping, sanitizer allowlists, markdown renderer, frontend framework trust APIs, DOMPurify-like configuration, CSP, URL parsing, entity decoding, and server/client rendering order
- every decode, sanitize, escape, rewrap, hydrate, or DOM insertion stage that can change the grammar or trust classification of the content
- negative evidence that storage points, alternate renderers, admin/staff views, notification templates, export/preview paths, and client-side hydration do not reintroduce executable context
- proof obligations for runtime sanitizer config, CSP deployment, CDN preview behavior, or browser-only transformations that cannot be verified statically

Record design/implementation conflicts when:
- documentation claims sanitized or markdown-only content but code later marks it trusted HTML
- CSP is cited as mitigation but the exploitable context allows same-origin script, inline script, unsafe protocols, or trusted-types bypasses
- one renderer escapes content while another renderer, admin panel, email template, preview, or frontend component unwraps it

If the final browser context cannot be identified for a high-risk content path, keep the gate `partial` or `blocked` and create coverage debt.

---

## Grep Starting Points

```bash
grep -rn 'innerHTML|outerHTML|insertAdjacentHTML|document\\.write|dangerouslySetInnerHTML' .
grep -rn '\\|safe\\b|html_safe|raw\\(|Html\\.Raw|{!!' .
grep -rn 'location\\.(hash|search)|postMessage|referrer|loadHTMLString|evaluateJavaScript' .
```

---

## Related References

- `references/application/vulnerabilities/xss-templates.md`
- `references/application/exploits/xss.md`
