# Skill Versioning Standard

The skill version tracks how much the audit framework itself changed, not the target project's risk level.

Current version:
- `4.1.0`

Version format:
- `MAJOR.MINOR.PATCH`

---

## Bump Rules

### PATCH

Increment the last digit for small changes that do not alter structure or reference layout.

Examples:
- wording improvements
- typo fixes
- clearer examples
- extra grep patterns
- small recommendation refinements
- progress display or execution-visibility refinements that do not change directory layout

### MINOR

Increment the middle digit when file-level content changes materially expand or alter coverage, while the overall structure stays compatible.

Examples:
- adding or substantially revising a vulnerability module
- adding or revising a framework or language reference file
- adding a reporting standard file within an existing directory
- changing report fields in a backward-compatible way
- adding backward-compatible coverage identity or independent verification controls

Reset `PATCH` to `0` when bumping `MINOR`.

### MAJOR

Increment the first digit when the skill structure changes in a way that affects loading paths, directory layout, or core workflow shape.

Examples:
- adding, removing, or renaming top-level reference directories
- moving major content classes between directories
- moving shared reference entry points to new directory paths that require loader updates
- moving core methodology files such as severity or coverage standards to new locations
- changing the audit category model or report schema in a breaking way
- restructuring how SKILL.md routes to reference modules

Reset `MINOR` and `PATCH` to `0` when bumping `MAJOR`.

---

## Reporting Requirement

Every generated report should include the current skill version in its metadata so future readers can understand which audit framework revision produced the output.
