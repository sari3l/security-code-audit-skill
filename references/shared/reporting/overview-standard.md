# Overview Standard

The report overview should help a decision-maker understand risk quickly without losing the path to technical detail.

---

## Required Sections

- project meta: date, mode, project, audit profile, knowledge domain, tech stack, files analyzed, and compiler reality for smart-contract audits when material
- executive summary: 2 to 3 sentences on overall posture and dominant risks
- risk overview by severity
- category coverage or domain coverage with counted states, plus notable blind spots
- top findings: only confirmed highest-signal items
- candidate signals: only unresolved high-signal cases worth explicit follow-up
- coverage debt: partial, blocked, or invalidated surfaces that still matter
- function call chains: bounded summary or appendix for security-relevant functions and state transitions in scope
- skill optimization suggestions: required when post-scan history replay finds still-live historical vulnerabilities that the current scan missed
- supplemental sections when material: operational risks, integration assumptions, and engineering notes that help readers without weakening the finding bar
- attack chains for Standard or Deep mode when multiple findings combine
- working-hypotheses appendix for Deep mode or beta `multi` when unresolved high-signal chains, trust assumptions, or shared-root-cause models remain material
- historical comparison: if the historical-miss gate passes, new, recurring, regressed, fixed; otherwise historical misses plus an explicit note that lifecycle comparison is withheld
- prioritized action items ordered by risk reduction

---

## Prioritization Rules

- prioritize exploitability and blast radius first
- favor findings with a clear minimal fix over broad wishlist items
- call out when one fix removes multiple downstream risks
- call out when individually moderate findings combine into materially higher impact, but only when the chain is supported by evidence
- use function-chain summaries to support later verification and attack-chain review, not to replace finding evidence
- summarize shared control failures and remediation leverage early, while keeping the most important exploit paths obvious in titles, attack vectors, impact, and attack-chain sections
- keep leadership-facing summary concise and engineer-facing action items specific
- never present candidate signals as if they were confirmed findings
- for artifact-centric audits of skill, agent, or instruction-bearing repos, summarize confirmed dangerous instructions early when material, while keeping benign examples in candidate or negative-evidence language instead of inventing a second verdict system
- if coverage debt is material, surface it near the top instead of burying it
- if historical misses exist, surface them near the top because they indicate active false-negative risk in the audit process
- keep supplemental sections clearly outside the severity table and confirmed finding count
- keep working hypotheses in an appendix so they remain visible without crowding the confirmed finding list
- in `quick`, `standard`, and `deep`, do not lead with "all prior findings fixed" unless each relevant prior fingerprint was explicitly reopened and revalidated against current code and the historical-miss gate found no still-live misses
