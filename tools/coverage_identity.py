#!/usr/bin/env python3
"""Build stable, source-derived identities for coverage ledger units."""

from __future__ import annotations

import argparse
import sys
import unicodedata
from dataclasses import dataclass
from typing import Final


_SAFE_ASCII: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_SEPARATOR: Final = "::"


class CoverageIdentityError(ValueError):
    """Raised when a coverage dimension cannot be canonicalized safely."""


@dataclass(frozen=True, slots=True)
class CoverageDimensions:
    """The source-derived dimensions that identify one review unit."""

    surface: str
    boundary: str
    subsystem: str
    attack_class: str
    lifecycle: str | None = None

    def as_id(self) -> str:
        """Return the canonical percent-encoded coverage ID."""
        values = [self.surface, self.boundary, self.subsystem, self.attack_class]
        if self.lifecycle is not None:
            values.append(self.lifecycle)
        return _SEPARATOR.join(_encode_reference(value) for value in values)


def coverage_id(
    *,
    surface: str,
    boundary: str,
    subsystem: str,
    attack_class: str,
    lifecycle: str | None = None,
) -> str:
    """Return a deterministic ID for one coverage ledger unit."""
    return CoverageDimensions(
        surface=surface,
        boundary=boundary,
        subsystem=subsystem,
        attack_class=attack_class,
        lifecycle=lifecycle,
    ).as_id()


def _encode_reference(value: str) -> str:
    normalized = _normalize_reference(value)
    encoded: list[str] = []
    for byte in normalized.encode("utf-8"):
        character = chr(byte)
        if character in _SAFE_ASCII:
            encoded.append(character)
        else:
            encoded.append(f"%{byte:02X}")
    return "".join(encoded)


def _normalize_reference(value: str) -> str:
    if not isinstance(value, str):
        raise CoverageIdentityError("coverage dimensions must be strings")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized or normalized != normalized.strip():
        raise CoverageIdentityError("coverage dimensions must be non-empty and trimmed")
    if any(_is_forbidden_character(character) for character in normalized):
        raise CoverageIdentityError(
            "coverage dimensions cannot contain control, format, or line-separator characters"
        )
    return normalized


def _is_forbidden_character(character: str) -> bool:
    category = unicodedata.category(character)
    return category.startswith("C") or category in {"Zl", "Zp"}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("surface")
    parser.add_argument("boundary")
    parser.add_argument("subsystem")
    parser.add_argument("attack_class")
    parser.add_argument("--lifecycle")
    return parser.parse_args()


def main() -> int:
    """Print one canonical coverage ID for shell and CI use."""
    args = _parse_args()
    try:
        value = coverage_id(
            surface=args.surface,
            boundary=args.boundary,
            subsystem=args.subsystem,
            attack_class=args.attack_class,
            lifecycle=args.lifecycle,
        )
    except CoverageIdentityError as exc:
        print(f"coverage identity error: {exc}", file=sys.stderr)
        return 2
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
