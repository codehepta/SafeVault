# SafeVault - Enhancement TODO List

This document tracks enhancements and improvements for the SafeVault secure coding starter project. Items are prioritized by security impact and implementation complexity.

## 🔴 Critical Priority

### 1. JWT Signing Key Security
**Issue:** Hardcoded JWT signing key in `Program.cs` (lines 74, 104)
- Key: `"SafeVault_Dev_Only_Super_Long_Key_Change_In_Production_12345"`
- **Risk:** Production deployments vulnerable if key not overridden
- **Impact:** Complete authentication bypass if key is compromised

**Action Items:**
- [ ] Add validation to reject weak/default keys in production
- [ ] Create `appsettings.Production.json` with environment variable override
- [ ] Document environment variable `JWT_SECRET_KEY` in deployment guide
- [ ] Add startup warning if default key is detected
- [ ] Consider Azure Key Vault or HashiCorp Vault integration

**Files:**
- `src/SafeVault/Program.cs`
- `src/SafeVault/appsettings.Production.json` (new)
- `DEPLOYMENT.md` (new)

---

### 2. CORS Policy Configuration
**Issue:** No explicit CORS configuration - defaults to allow all origins
- **Risk:** API vulnerable to cross-origin attacks
- **Impact:** CSRF, data exfiltration via malicious frontend

**Action Items:**
- [ ] Add `builder.Services.AddCors()` with explicit origin allowlist
- [ ] Define development and production origin sets
- [ ] Apply CORS middleware before authentication
- [ ] Document CORS configuration in appsettings
- [ ] Add tests for CORS preflight requests

**Files:**
- `src/SafeVault/Program.cs`
- `src/SafeVault/appsettings.json`
- `tests/SafeVault.Tests/TestCorsSecurity.cs` (new)

---

### 3. Rate Limiting Protection
**Issue:** No protection against brute-force attacks on authentication endpoints
- **Risk:** Credential stuffing, token brute-force, DoS
- **Impact:** Account compromise, service degradation

**Action Items:**
- [ ] Install `AspNetCoreRateLimit` or use built-in .NET 7+ rate limiting
- [ ] Configure per-IP rate limits for `/api/auth/login` (5/minute)
- [ ] Configure per-IP rate limits for `/api/auth/register` (2/minute)
- [ ] Configure per-IP rate limits for `/api/auth/refresh` (10/minute)
- [ ] Add rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`)
- [ ] Add tests for rate limit enforcement

**Files:**
- `src/SafeVault/Program.cs`
- `src/SafeVault/appsettings.json`
- `tests/SafeVault.Tests/TestRateLimiting.cs` (new)

**Dependencies:**
```xml
<PackageReference Include="AspNetCoreRateLimit" Version="5.0.0" />
```

---

## ⚠️ High Priority

### 4. Content Security Policy (CSP)
**Issue:** No CSP headers to mitigate XSS attacks
- **Risk:** Inline script execution if XSS filter bypassed
- **Impact:** XSS, data exfiltration, session hijacking

**Action Items:**
- [ ] Add CSP middleware with strict policy
- [ ] Policy: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;`
- [ ] Enable `report-uri` for CSP violations
- [ ] Add CSP nonce support for inline scripts if needed
- [ ] Add tests to verify CSP headers

**Files:**
- `src/SafeVault/Middleware/ContentSecurityPolicyMiddleware.cs` (new)
- `src/SafeVault/Program.cs`
- `tests/SafeVault.Tests/TestSecurityHeaders.cs` (new)

---

### 5. Username Normalization
**Issue:** Usernames not normalized to lowercase (unlike emails)
- **Risk:** `alice` and `ALICE` can create separate accounts
- **Impact:** Confusion, impersonation, duplicate accounts

**Action Items:**
- [ ] Add `username.ToLowerInvariant()` in `InputValidator.ValidateAndNormalizeUsername()`
- [ ] Update registration endpoint to normalize before storage
- [ ] Update login endpoint to normalize before lookup
- [ ] Add migration to lowercase existing usernames in database
- [ ] Add test for case-insensitive username uniqueness

**Files:**
- `src/SafeVault/Security/InputValidator.cs`
- `src/SafeVault/Program.cs` (register/login endpoints)
- `tests/SafeVault.Tests/TestInputValidation.cs`

**Breaking Change:** Requires database migration if users exist

---

### 6. Refresh Token Cleanup
**Issue:** Revoked refresh tokens accumulate in database
- **Risk:** Database bloat, performance degradation
- **Impact:** Increased storage costs, slower queries

**Action Items:**
- [ ] Add `IHostedService` background job to clean expired tokens
- [ ] Run cleanup every 24 hours
- [ ] Delete tokens where `ExpiresAt < DateTime.UtcNow` and `IsRevoked = true`
- [ ] Add configurable retention policy (default: 7 days after revocation)
- [ ] Log cleanup statistics

**Files:**
- `src/SafeVault/Services/RefreshTokenCleanupService.cs` (new)
- `src/SafeVault/Program.cs`
- `src/SafeVault/appsettings.json`

---

### 7. Remove Legacy LoginService
**Issue:** Duplicate authentication logic creates maintenance burden
- `LoginService.cs` uses direct SQL (legacy)
- Modern code uses ASP.NET Identity
- **Impact:** Code duplication, confusion for developers

**Action Items:**
- [ ] Mark `LoginService.cs` as `[Obsolete]` or move to separate "legacy examples" folder
- [ ] Remove from DI registration
- [ ] Update tests to use Identity-based authentication only
- [ ] Document migration path from legacy to Identity

**Files:**
- `src/SafeVault/Security/LoginService.cs`
- `tests/SafeVault.Tests/TestLoginSecurity.cs`

**Alternative:** Keep as reference example with clear documentation

---

## 📋 Medium Priority

### 8. Additional Security Tests
**Issue:** Testing gaps for edge cases and failure scenarios

**Action Items:**
- [ ] Test: Rate limiting after 10+ failed logins
- [ ] Test: Expired access token rejection
- [ ] Test: Revoked refresh token cannot issue new tokens
- [ ] Test: Username case collision (alice vs. ALICE)
- [ ] Test: HTTP → HTTPS redirect with 308 status
- [ ] Test: HSTS header presence and values
- [ ] Test: Password strength policy enforcement
- [ ] Test: JWT claim tampering detection
- [ ] Test: Concurrent login sessions
- [ ] Test: CORS preflight with invalid origin

**Files:**
- `tests/SafeVault.Tests/TestRateLimiting.cs` (new)
- `tests/SafeVault.Tests/TestTokenExpiration.cs` (new)
- `tests/SafeVault.Tests/TestHttpsEnforcement.cs` (new)
- `tests/SafeVault.Tests/TestInputValidation.cs` (expand)

**Target Coverage:** 80%+ line coverage on Security/ folder

---

### 9. Deployment Documentation
**Issue:** No production deployment guidance

**Action Items:**
- [ ] Create `DEPLOYMENT.md` with step-by-step checklist
- [ ] Document environment variables (JWT key, database connection, CORS origins)
- [ ] Document HTTPS certificate setup (Let's Encrypt, Azure, etc.)
- [ ] Document database migration workflow
- [ ] Document secrets management best practices
- [ ] Create pre-flight deployment checklist
- [ ] Add troubleshooting section

**Files:**
- `DEPLOYMENT.md` (new)
- `README.md` (add link to deployment guide)

---

### 10. Security Configuration Guide
**Issue:** No centralized configuration documentation

**Action Items:**
- [ ] Create `SECURITY_CONFIG.md` explaining each setting
- [ ] Document password policy options
- [ ] Document JWT token lifetime trade-offs
- [ ] Document CORS configuration options
- [ ] Document rate limiting thresholds
- [ ] Document HTTPS/HSTS settings
- [ ] Add security hardening checklist

**Files:**
- `SECURITY_CONFIG.md` (new)

---

### 11. API Documentation Enhancement
**Issue:** Swagger UI lacks endpoint descriptions

**Action Items:**
- [ ] Add XML comments to minimal API handlers (`Program.cs`)
- [ ] Document request/response models
- [ ] Add example request payloads
- [ ] Document error responses (400, 401, 403, 500)
- [ ] Document authentication flow with code examples
- [ ] Add `[ProducesResponseType]` attributes

**Files:**
- `src/SafeVault/Program.cs`

---

### 12. Request Logging & Correlation IDs
**Issue:** Limited audit trail for security incidents

**Action Items:**
- [ ] Add correlation ID middleware (X-Correlation-ID header)
- [ ] Log correlation ID with all security events
- [ ] Add structured logging with Serilog
- [ ] Log request method, path, status, duration
- [ ] Sanitize sensitive data in logs (passwords, tokens)
- [ ] Add optional request/response body logging for debugging

**Files:**
- `src/SafeVault/Middleware/CorrelationIdMiddleware.cs` (new)
- `src/SafeVault/Program.cs`

**Dependencies:**
```xml
<PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />
```

---

## 💡 Low Priority / Nice-to-Have

### 13. Database Schema Cleanup
**Issue:** `database/database.sql` uses MySQL syntax but project uses SQLite

**Action Items:**
- [ ] Update schema to SQLite syntax
- [ ] Remove AUTO_INCREMENT, use INTEGER PRIMARY KEY for autoincrement
- [ ] Add indexes for username/email lookup
- [ ] Document as reference only (migrations create tables)

**Files:**
- `database/database.sql`

---

### 14. Password Breach Detection
**Issue:** No check against compromised password databases

**Action Items:**
- [ ] Integrate Have I Been Pwned API
- [ ] Add optional password breach check during registration
- [ ] Hash password with SHA-1 before API lookup (k-anonymity)
- [ ] Make check configurable (off by default for privacy)
- [ ] Add test for breach detection

**Files:**
- `src/SafeVault/Security/PasswordBreachChecker.cs` (new)
- `src/SafeVault/Program.cs`

**Dependencies:**
```xml
<PackageReference Include="HaveIBeenPwned.Client" Version="1.4.0" />
```

---

### 15. MFA/2FA Support
**Issue:** Single-factor authentication only

**Action Items:**
- [ ] Add TOTP authenticator support (Google Authenticator, Authy)
- [ ] Use ASP.NET Identity 2FA APIs
- [ ] Add QR code generation for authenticator setup
- [ ] Add backup codes for account recovery
- [ ] Require MFA for Admin role
- [ ] Add tests for 2FA flow

**Files:**
- `src/SafeVault/Controllers/MfaController.cs` (new)
- `src/SafeVault/Program.cs`
- `tests/SafeVault.Tests/TestMfaAuthentication.cs` (new)

**Dependencies:**
```xml
<PackageReference Include="QRCoder" Version="1.4.3" />
```

---

### 16. Threat Model Documentation
**Issue:** No explicit threat model or attack surface analysis

**Action Items:**
- [ ] Create `THREAT_MODEL.md` with STRIDE analysis
- [ ] Document trust boundaries (client, API, database)
- [ ] List assets (user credentials, JWT keys, personal data)
- [ ] Identify threats per category (Spoofing, Tampering, Repudiation, etc.)
- [ ] Map existing controls to threats
- [ ] Identify residual risks

**Files:**
- `THREAT_MODEL.md` (new)

---

### 17. Development Setup Guide
**Issue:** No developer onboarding documentation

**Action Items:**
- [ ] Create `DEVELOPMENT.md` with setup steps
- [ ] Document prerequisites (.NET SDK version, IDE recommendations)
- [ ] Document local HTTPS certificate trust
- [ ] Document database initialization
- [ ] Document test execution workflow
- [ ] Add troubleshooting section

**Files:**
- `DEVELOPMENT.md` (new)

---

### 18. Authentication Flow Diagram
**Issue:** Text-only explanation of JWT refresh flow

**Action Items:**
- [ ] Create sequence diagram for login → access token → refresh flow
- [ ] Document token lifetime and rotation
- [ ] Visualize client-server interaction
- [ ] Add diagram to README.md

**Tools:** Mermaid.js, PlantUML, or draw.io

---

### 19. Session Management
**Issue:** No explicit session timeout or revocation

**Action Items:**
- [ ] Add sliding session expiration for web UI
- [ ] Add logout endpoint to revoke all user tokens
- [ ] Add "logout all devices" functionality
- [ ] Track active sessions in database
- [ ] Add session list UI in profile page

**Files:**
- `src/SafeVault/Controllers/SessionController.cs` (new)

---

### 20. IP Whitelisting for Admin
**Issue:** Admin endpoints accessible from any IP

**Action Items:**
- [ ] Add IP address restriction middleware
- [ ] Configure admin IP allowlist in appsettings
- [ ] Apply to `/api/admin/*` endpoints
- [ ] Log blocked access attempts
- [ ] Make configurable (off by default)

**Files:**
- `src/SafeVault/Middleware/IpWhitelistMiddleware.cs` (new)

---

## 📊 Test Coverage Goals

**Current Coverage:** ~60% estimated (26 tests)

**Target Coverage:**
- Security/ folder: 80%+
- Data/ folder: 70%+
- Overall: 75%+

**Test Metrics:**
- [ ] Enable code coverage reporting (`dotnet test --collect:"XPlat Code Coverage"`)
- [ ] Integrate with coverage visualization tool (Coverlet, ReportGenerator)
- [ ] Add coverage badge to README.md

---

## 🔧 Code Quality Improvements

### DRY Violations
- [ ] Extract JWT key configuration to single location (lines 74, 104 in Program.cs)
- [ ] Consolidate login validation logic between MVC controller and API endpoint
- [ ] Create shared validation helper for email/username

### Refactoring Opportunities
- [ ] Move entity configuration from DbContext to separate IEntityTypeConfiguration classes
- [ ] Extract middleware registration to extension methods
- [ ] Create appsettings section classes for typed configuration

---

## 📚 Documentation Enhancements

- [ ] Add "What's Covered" section to README with checklist
- [ ] Add "What's NOT Covered" section (e.g., OAuth2, SAML, mobile auth)
- [ ] Create CONTRIBUTING.md for community contributions
- [ ] Add LICENSE file (if open source)
- [ ] Add CHANGELOG.md to track version history
- [ ] Add issue templates for GitHub (bug report, feature request)
- [ ] Add pull request template

---

## 🎯 Long-Term Roadmap

### Phase 1 (Current - Security Hardening)
- Critical and high priority items
- Estimated: 2-3 weeks

### Phase 2 (Enhanced Features)
- Medium priority items
- MFA, rate limiting, advanced logging
- Estimated: 4-6 weeks

### Phase 3 (Enterprise Features)
- OAuth2/OIDC integration
- Audit trail database
- API key management
- Estimated: 8-12 weeks

---

## 🚀 Quick Wins (Can Complete in <1 hour)

1. [ ] Add CSP middleware (30 min)
2. [ ] Normalize usernames to lowercase (15 min)
3. [ ] Add startup warning for default JWT key (10 min)
4. [ ] Fix database.sql to SQLite syntax (10 min)
5. [ ] Add XML comments to API endpoints (30 min)
6. [ ] Create DEVELOPMENT.md (20 min)
7. [ ] Add CORS configuration (20 min)
8. [ ] Add correlation ID middleware (30 min)

**Total Quick Wins Time:** ~3 hours for 8 improvements

---

## 📝 Notes

- All security enhancements should maintain backward compatibility unless explicitly marked as breaking changes
- Test coverage must not decrease with new features
- All changes should be reviewed against OWASP Top 10 and ASVS guidelines
- Documentation updates are mandatory for user-facing changes

---

## 🔗 References

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP ASVS 4.0](https://owasp.org/www-project-application-security-verification-standard/)
- [ASP.NET Core Security Best Practices](https://learn.microsoft.com/en-us/aspnet/core/security/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

*Last Updated: 2026-02-15*
*Maintained by: SafeVault Project Team*
