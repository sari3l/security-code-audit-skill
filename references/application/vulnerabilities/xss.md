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
