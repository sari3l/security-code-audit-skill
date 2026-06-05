"""Optional stdlib assurance helpers for security-code-audit.

These helpers are deliberately advisory. They preserve raw signals first and
never prove that a project is safe because a normalized record is absent.
"""

from .common import Issue, emit_json, read_json, read_jsonl, write_jsonl

__all__ = ["Issue", "emit_json", "read_json", "read_jsonl", "write_jsonl"]
