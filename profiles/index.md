# Target Profile Index

These files define target-type semantics after recon. They are not scan-depth modes and they are not reference knowledge. Their job is to make stage labels and post-recon emphasis match the actual audit target.

Use profiles to answer:
- what kind of system is this repo primarily
- which progress language should the user see after recon
- which cross-cutting audit emphasis should dominate stages `3/6` to `5/6`

---

## Available Profiles

- `profiles/application.md`
  Default web, API, service, backend, and full-stack application profile.

- `profiles/smart-contract.md`
  Solidity and contract-heavy repos where on-chain trust, accounting, signatures, upgradeability, and economic abuse matter more than web-style Top 10 framing.

- `profiles/artifact-centric.md`
  Repos dominated by markdown, skill files, prompts, specs, notebooks, and other instruction-bearing or rendered assets, with little runtime application logic.

---

## Selection Rules

Choose exactly one profile after recon and before stage `3/6`.

Use `smart-contract` when:
- `.sol` is the primary code surface
- Foundry or Hardhat indicators exist
- the main trust model is on-chain logic, token accounting, signatures, proxies, or oracle assumptions

Use `artifact-centric` when:
- the repo is primarily `SKILL.md`, `AGENTS.md`, prompt files, markdown, API specs, or notebooks
- there is little meaningful runtime application code compared with artifact surface

Otherwise use:
- `application`

If multiple surfaces exist, choose the dominant audit target, not just the first file type found.

---

## Progress Rules

- stages `1/6`, `2/6`, and `6/6` remain shared
- before recon completes, stages `3/6`, `4/6`, and `5/6` must stay neutral placeholders
- after recon completes, stages `3/6`, `4/6`, and `5/6` come from the active profile for the active mode
- replace stages `3/6`, `4/6`, and `5/6` in place without changing the overall `[1/6]` to `[6/6]` plan order
- `regression` stays profile-independent and continues using `modes/regression.md`

---

## Design Intent

Profiles exist because:
- mode describes audit depth
- execution describes agent topology
- profile describes target semantics
- domain describes which knowledge corpus is primary after recon

Do not collapse those four concerns back together.
