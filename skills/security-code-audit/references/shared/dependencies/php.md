# PHP Dependency Audit

## Detect

- `composer.json`
- `composer.lock`
- `vendor/`

## Preferred Audit Paths

```bash
composer audit --locked
composer show -t
```

## What To Check

- direct vs transitive vulnerable packages
- abandoned packages and unsupported framework versions
- plugins with broad execution privileges
- `require-dev` packages accidentally present in production images
- private repository trust and package source pinning
- vendored code checked in outside Composer's lock state

## Common High-Risk Cases

- old Laravel or Symfony chains
- vulnerable parser or image libraries
- PHPUnit, debugbar, Telescope, or admin tooling exposed in production
- one service copies `vendor/` from a different build than `composer.lock`

## Reporting Notes

- Record if the issue comes from `require` or `require-dev`.
- Do not dismiss dev packages automatically if deployment images include them.
