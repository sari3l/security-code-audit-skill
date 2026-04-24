# JavaScript and TypeScript Dependency Audit

## Detect

- `package.json`
- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- workspace roots and per-package manifests in monorepos

## Preferred Audit Paths

Use the package manager the repo actually uses.

```bash
npm audit --package-lock-only
pnpm audit
yarn npm audit
yarn audit
```

Helpful supporting commands:

```bash
npm ls --all
pnpm why <package>
yarn why <package>
```

## What To Check

- direct vs transitive vulnerable packages
- workspace lock-file drift across apps and packages
- `resolutions`, `overrides`, aliases, and patched packages that hide the real vulnerable version
- dev tools that may ship in server images or exposed routes
- browser-shipped dependencies vs server-only dependencies
- native addons or downloaded binaries in postinstall scripts

## Common High-Risk Libraries

- auth and session packages
- markdown and HTML sanitizers
- archive and image parsers
- HTTP clients and proxy helpers
- template engines and SSR packages

## Reporting Notes

- Record the exact package manager command used.
- Note whether the vulnerable package is in a workspace app, shared package, or root tooling.
- Treat build-only packages carefully, but do not auto-dismiss them if CI, dev servers, or preview environments are reachable.
