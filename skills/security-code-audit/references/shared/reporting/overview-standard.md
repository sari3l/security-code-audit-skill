# Overview Standard

The report overview should help a decision-maker understand risk quickly without losing the path to technical detail.

---

## Required Sections

- project meta: date, mode, report style, project, skill version, audit profile, knowledge domain, tech stack, files analyzed, and compiler reality for smart-contract audits when material
- executive summary: 2 to 3 sentences on overall posture and dominant risks
- risk overview by severity
- category coverage or domain coverage, plus notable blind spots
- top findings: only confirmed highest-signal items
- candidate signals: only unresolved high-signal cases worth explicit follow-up
- coverage debt: partial, blocked, or invalidated surfaces that still matter
- supplemental sections when material: operational risks, integration assumptions, and engineering notes that help readers without weakening the finding bar
- attack chains for Standard or Deep mode when multiple findings combine
- working-hypotheses appendix for Deep mode or beta `multi` when unresolved high-signal chains, trust assumptions, or shared-root-cause models remain material
- historical comparison: new, recurring, regressed, fixed
- prioritized action items ordered by risk reduction

---

## Prioritization Rules

- prioritize exploitability and blast radius first
- favor findings with a clear minimal fix over broad wishlist items
- call out when one fix removes multiple downstream risks
- follow the active report style for framing:
  - governance should summarize shared control failures and remediation leverage first
  - exploit-first should make the most operationally important attacker capability obvious early
- keep leadership-facing summary concise and engineer-facing action items specific
- never present candidate signals as if they were confirmed findings
- if coverage debt is material, surface it near the top instead of burying it
- keep supplemental sections clearly outside the severity table and confirmed finding count
- keep working hypotheses in an appendix so they remain visible without crowding the confirmed finding list
