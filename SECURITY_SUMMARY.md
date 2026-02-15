# Security Summary

## Vulnerabilities Identified

- Potential role escalation during registration: client input could request elevated roles (`Admin`, `Guest`) during account creation.
- SQL injection attack attempts needed explicit coverage in API-level login paths (even with parameterized queries in data access).
- XSS payload handling gaps for some patterns (for example unquoted event handlers and `srcdoc`/iframe fragments).
- Missing anti-forgery validation on MVC login form POST action.
- HTTPS enforcement needed stronger defaults for secure transport across environments.

## Fixes Applied

- Enforced server-side role assignment during registration: new users are always created with `User` role.
- Kept all database access on parameterized queries and added stricter username normalization before query execution.
- Hardened input validation and XSS protections:
  - Added stricter username/email normalization.
  - Added XSS detection for script tags, event handlers (quoted/unquoted), `javascript:` payloads, iframe/srcdoc patterns.
  - Added sanitization cleanup for malformed iframe-tag scenarios.
- Added `[ValidateAntiForgeryToken]` to MVC login POST.
- Hardened HTTPS configuration:
  - Permanent HTTPS redirects.
  - HSTS policy.
  - Forwarded header handling for proxy deployments.
  - HTTPS-first local run guidance.

## Verification

- Added/updated tests for:
  - SQL injection payload attempts against lookup/login paths.
  - XSS payload attempts in form fields and API login/register endpoints.
  - Role escalation attempt during registration.
- Current solution build: **0 warnings, 0 errors**.
- Current security test runs: all passing.
