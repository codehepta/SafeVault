# Security Summary

## Vulnerabilities Identified

- Potential role escalation during registration: client input could request elevated roles (`Admin`, `Guest`) during account creation.
- SQL injection attack attempts needed explicit coverage in API-level login paths (even with parameterized queries in data access).
- XSS payload handling gaps for some patterns (for example unquoted event handlers and `srcdoc`/iframe fragments).
- Missing anti-forgery validation on MVC login form POST action.
- HTTPS enforcement needed stronger defaults for secure transport across environments.
- **[2026-02-15] CRITICAL: Hardcoded JWT signing key in production environments** - default development key could be used in production deployments, leading to complete authentication bypass.
- **[2026-02-15] CRITICAL: Missing rate limiting on authentication endpoints** - no protection against brute-force attacks, credential stuffing, or DoS attacks.
- **[2026-02-15] Missing test coverage for CORS preflight requests** - existing CORS configuration was not validated with automated tests.

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
- **[2026-02-15] JWT Signing Key Security Hardening:**
  - Added fail-fast validation to reject weak or default JWT keys in production environments
  - Explicitly validates minimum key length (32 characters) at startup
  - Throws exception if default development key is detected in production
  - Provides clear error messages with guidance on key generation (`openssl rand -base64 48`)
  - Extracted `IsProductionEnvironment()` helper to avoid code duplication
  - Allows Development and Testing environments while strictly enforcing production security
- **[2026-02-15] Rate Limiting Protection:**
  - Implemented using .NET 8 built-in rate limiting (no external dependencies)
  - Per-IP rate limits configured for authentication endpoints:
    - `/api/auth/login`: 5 requests/minute
    - `/api/auth/register`: 2 requests/minute
    - `/api/auth/refresh`: 10 requests/minute
  - Global rate limit: 100 requests/minute per IP for other endpoints
  - Returns HTTP 429 (Too Many Requests) with `Retry-After` header
  - Custom JSON error messages for rate-limited requests
  - Prevents brute-force attacks, credential stuffing, and DoS
- **[2026-02-15] CORS Test Coverage:**
  - Added 4 comprehensive tests for CORS preflight and actual requests
  - Validates allowed origins are accepted
  - Validates disallowed origins are rejected
  - Confirms explicit origin allowlist (not wildcard)
  - Tests multiple configured origins

## Verification

- Added/updated tests for:
  - SQL injection payload attempts against lookup/login paths.
  - XSS payload attempts in form fields and API login/register endpoints.
  - Role escalation attempt during registration.
  - **[2026-02-15] CORS preflight requests** (4 new tests)
  - **[2026-02-15] Rate limiting enforcement** (6 new tests)
- Current solution build: **0 warnings, 0 errors**.
- Current security test runs: **all 47 tests passing** (up from 36 tests).
- **[2026-02-15] CodeQL Security Scan:** 0 vulnerabilities detected.
