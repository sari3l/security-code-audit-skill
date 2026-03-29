# Governance Report Style Sample

## Meta
- **Date**: 2026-03-29 12:34:06 CST
- **Skill Version**: 1.0.4
- **Mode**: deep
- **Report Style**: governance
- **Audit Profile**: application
- **Knowledge Domain**: application
- **Project**: nomad-control-api

## Executive Summary
This governance-style sample keeps one missing control boundary as the primary finding because the failed authorization check, trust boundary, and remediation plan are materially shared. The downstream exploit paths remain visible through the finding body and attack-chain section instead of being promoted into separate headline findings.

## Risk Overview
| Severity | Count |
|----------|-------|
| Critical | 1 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |
| Info     | 0 |

## Confirmed Findings

### CRIT-001: Missing authorization on the Nomad control plane allows arbitrary cluster actions
- **Severity**: Critical
- **Maturity**: Confirmed
- **Category / Surface**: C3 Authorization
- **Fingerprint**: `authz.nomad.control-plane.public-cluster-admin`
- **Location**: `internal/http/jobs.go:42`, `internal/http/files.go:61`, `internal/http/control.go:88`
- **Status**: New
- **Description**: Publicly reachable Nomad control endpoints accept unauthenticated requests and forward them into privileged cluster operations.
- **Attack Vector**: An anonymous attacker can submit an arbitrary `jobSpec`, use the same control surface to read job-connected files, and stop or inspect workloads without prior trust.
- **Impact**: Arbitrary workload execution, unauthorized file access, and unauthorized workload disruption all become reachable through one missing authorization boundary.
- **PoC**: `curl -X POST /v1/jobs -d @attacker-job.json`
- **Evidence**:
  ```go
  router.POST("/v1/jobs", submitJob)
  router.GET("/v1/files/:id", readFile)
  router.POST("/v1/jobs/:id/stop", stopJob)
  ```
- **Minimal Fix**: Require authenticated and authorized access before any control-plane handler can submit, inspect, read, or stop Nomad workloads.
- **Hardening**: Add per-action authorization, audit logging, and deny-by-default control-plane routing.
- **Related Findings**: Attack chains should call out arbitrary job submission, file access, and stop operations as downstream paths of this same control failure.

## Candidate Signals

### CAND-001: Nomad status endpoint may also leak task environment data
- **Category / Surface**: C5 Data Exposure
- **Fingerprint**: `authz.nomad.control-plane.public-cluster-admin`
- **Location**: `internal/http/status.go:33`
- **Suspicion**: The status response appears to include task metadata that may expose secrets or file paths when called anonymously.
- **Why Not Confirmed Yet**: The sample does not include a captured response proving that sensitive fields are always returned.
- **Negative Evidence or Blocker**: The serializer may redact fields in some deployment modes.
- **Next Verification Step**: Capture an unauthenticated status response from a live deployment or integration test fixture.

## Coverage Debt

### DEBT-001: Worker-side ACL enforcement was not retested
- **State**: Partial
- **Reason**: The sample focuses on HTTP control-plane handlers, not downstream worker ACL middleware.
- **Risk If Wrong**: Some exploit paths may collapse at runtime while others still succeed, changing the exact blast radius.
- **Re-Audit Trigger**: Any ACL, proxy, or gateway change around Nomad control routes.
- **Suggested Next Step**: Retest the same job lifecycle through an environment with real worker-side policy enforcement enabled.

## Critical Attack Chains

1. Anonymous HTTP request -> unauthenticated job submission -> attacker-controlled workload execution -> follow-on file read and stop operations from the same control boundary.

## Historical Context

- No prior governance report existed for this timestamp family, so this finding is tracked as `New`.
- This presentation keeps the root cause and its downstream exploit paths in one governance finding because the remediation boundary is shared.
