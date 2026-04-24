# Logging And Monitoring

Use this module for C11 when the repo logs auth, requests, jobs, errors, or security events.

## What To Audit

- secrets, tokens, passwords, cookies, API keys, and reset links written to logs
- PII or financial data logged without masking
- full request or response bodies logged on sensitive paths
- log injection through newlines, delimiters, or structured log fields
- missing security event logs for login, reset, role change, admin action, export, upload replace, or repeated failures
- missing alerting or counters for brute force, token abuse, or repeated authorization failures
- log storage exposed by weak file permissions, public buckets, or debug endpoints

## High-Risk Patterns

- request dump middleware on auth or payment routes
- `console.log`, `print`, or debug logging of credentials and tokens
- raw SQL or stack trace logging with secrets embedded
- log viewers or downloadable log files without authorization
- untrusted input concatenated directly into log lines

## Audit Method

1. Locate loggers, middleware, interceptors, exception handlers, and audit-event publishers.
2. Trace sensitive inputs through auth, reset, payment, upload, and admin paths.
3. Verify masking, redaction, and field allowlists instead of best-effort deny lists.
4. Check whether security-relevant events are logged and whether repeated failures can be detected.
5. Check where logs are stored, who can read them, and whether log viewers or collectors are exposed.

## Grep Starters

- `logger`
- `audit`
- `console.log`
- `print(`
- `log.info`
- `log.error`
- `request.body`
- `Authorization`
- `password`
- `token`

## Safe Patterns

- structured logging with explicit safe fields
- redaction before logging
- separate audit-event logging for security actions
- access-controlled log viewers and collectors
- alerting tied to repeated failure patterns
