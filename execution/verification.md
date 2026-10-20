# Independent Verification Contract

Use this contract after discovery and before a confirmed finding enters the
canonical findings JSONL.

## Candidate pass

Consolidate candidates by stable fingerprint and root cause. Each candidate
must include a complete source trace, the strongest visible control, the
affected principal/resource, and the exact fact that is still missing when it
cannot be confirmed.

## Fresh verifier

Give every candidate that may become `confirmed` to a fresh verifier that did
not discover it. The verifier must:

1. reread every cited source location and reconstruct the entrypoint-to-sink
   path;
2. search for the strongest preventing layer, sibling path, and alternate
   lifecycle or transport;
3. reproduce only the minimum local result that settles the claim, inside
   `core/execution-safety.md`;
4. keep `candidate`/`needs_validation` when a deployment or runtime fact is
   decisive and source/local evidence cannot answer it;
5. return `negative_closed`/`rejected` only with concrete disproof or stable
   isolation evidence.

The verifier receives the candidate and current source facts, but not another
verifier's conclusion. A material change to root cause, trace, observed impact,
or severity requires another fresh verifier.

## Coverage critic

After each multi-agent hunting wave, a fresh coverage critic checks the full
ledger for unmapped entrypoints, parallel paths, lifecycle modes, unjustified
exclusions, unresolved prior work, and units closed without owned evidence.
Accepted gaps become deterministic coverage units. In single-agent execution,
perform one end-of-scan critic pass and record its result; it must not be
described as complete coverage when it was not run.

## State

When verification is material, persist a `verification-ledger.jsonl` row with:

```json
{
  "id": "verify-...",
  "candidate_fingerprint": "...",
  "stage": "candidate|final_record",
  "verifier_id": "...",
  "independence": "fresh_agent|fresh_pass|unavailable",
  "decision": "confirmed|needs_validation|rejected",
  "source_rechecked": true,
  "local_check": "none|bounded_fixture|sandbox_blocked",
  "evidence_refs": [],
  "blockers": []
}
```

`independence: unavailable` cannot support a complete high-assurance claim
for a Critical or High finding. Keep that record as a candidate until a fresh
verifier is available, or disclose the incomplete state and blocker.

Before reporting a confirmed finding, persist a `final_record` row with its exact
fingerprint, `decision: confirmed`, `source_rechecked: true`, and no remaining
blockers. An empty ledger or a verifier decision for another fingerprint does
not satisfy the report gate. A `fresh_pass` describes a separate reread by the
same auditor when delegation is unavailable; it must not be labeled a fresh agent.
