from __future__ import annotations

from dataclasses import dataclass
from typing import Any


ALLOWED_EFFECTS = {
    "agent_call",
    "browser_profile_access",
    "code_eval",
    "dependency_mutation",
    "env_read",
    "env_write",
    "fs_read",
    "fs_write",
    "net_read",
    "net_write",
    "persistence",
    "proc_exec",
}

ALLOWED_TRIGGERS = {
    "manual",
    "external",
    "llm",
    "on_import",
    "on_install",
    "scheduled",
    "unknown",
}

ALLOWED_GATE_STRENGTHS = {"none", "weak", "strong", "unknown"}
ALLOWED_PATH_STATUS = {
    "blocked",
    "bounded",
    "candidate",
    "confirmed",
    "coverage_debt",
    "negative_evidence",
    "unmapped_signal",
}
ALLOWED_CLAIMS = {
    "credential_bound",
    "local_only",
    "no_fs_write",
    "no_network",
    "read_only",
}

DANGEROUS_EFFECTS = {
    "agent_call",
    "browser_profile_access",
    "code_eval",
    "dependency_mutation",
    "env_write",
    "fs_write",
    "net_write",
    "persistence",
    "proc_exec",
}

CLAIM_BLOCKED_EFFECTS = {
    "read_only": {
        "dependency_mutation",
        "env_write",
        "fs_write",
        "net_write",
        "persistence",
        "proc_exec",
    },
    "local_only": {"agent_call", "net_read", "net_write"},
    "no_network": {"agent_call", "net_read", "net_write"},
    "no_fs_write": {"fs_write", "persistence"},
}


@dataclass(frozen=True)
class SeedMatch:
    reason: str
    effects: tuple[str, ...]
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    resources: tuple[str, ...] = ()
    trigger: str = "manual"
    gate: str = "unknown"
    gate_strength: str = "unknown"
    path_status: str = "candidate"

    def to_capability(self, *, record_id: str, scope: str, evidence_ref: str) -> dict[str, Any]:
        return {
            "id": record_id,
            "scope": scope,
            "reason": self.reason,
            "effects": list(self.effects),
            "sources": list(self.sources),
            "sinks": list(self.sinks),
            "resources": list(self.resources),
            "trigger": self.trigger,
            "gate": self.gate,
            "gate_strength": self.gate_strength,
            "path_status": self.path_status,
            "freshness_status": "fresh_current",
            "evidence_refs": [evidence_ref],
        }
