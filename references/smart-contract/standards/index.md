# Smart-Contract Standards Overlay

Use this directory when you need to translate the contract audit into external standards language such as OWASP Smart Contracts Top 10 or SCSVS architecture controls.

These files are overlays, not the primary audit path.

Use them to:
- explain which standard items are already covered by the current contract methodology
- identify where coverage is only partial or still implicit
- avoid claiming standard coverage that the current skill does not actually implement

Do not use them to replace:
- `references/smart-contract/vulnerabilities/index.md`
- `references/smart-contract/languages/index.md`
- `references/smart-contract/exploits/index.md`

---

## Modules

- `references/smart-contract/standards/owasp-sc-top10.md`
  Mapping between OWASP Smart Contracts Top 10 items and the current contract audit modules.

- `references/smart-contract/standards/scsvs-arch.md`
  Mapping between SCSVS architecture-oriented checks and the current contract audit modules.

---

## Status Language

Use these labels in standards overlays:
- `Explicit`
  A current contract module covers this item directly and intentionally.
- `Partial`
  The current skill touches the item, but not as a dedicated or complete control.
- `Gap`
  The item is not covered clearly enough today to claim meaningful support.

Standards overlays should stay honest. Prefer `Partial` or `Gap` over overstating coverage.
