# SafeVault

Secure coding starter project for validating user input, preventing SQL injection with parameterized queries, and testing against common web vulnerabilities.

## 📚 Documentation

- **[TODO.md](TODO.md)** - Prioritized enhancement roadmap with 20+ security improvements
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide with security checklist
- **[SECURITY_SUMMARY.md](SECURITY_SUMMARY.md)** - Security vulnerabilities identified and fixed

## Project Structure

- `src/SafeVault`: Secure application logic
  - `Helpers/`: Shared utility helpers
  - `Security/InputValidator.cs`: Input validation and HTML sanitization
  - `Security/PasswordHasher.cs`: PBKDF2 password hashing and verification helper
  - `Security/LoginService.cs`: Legacy secure login helper used by unit tests
  - `Security/JwtTokenService.cs`: JWT access/refresh token issuing and validation setup
  - `Security/IdentitySeeder.cs`: Identity role and default user seeding
  - `Security/AuthorizationService.cs`: Role-based authorization checks
  - `Middleware/ContentSecurityPolicyMiddleware.cs`: CSP and security headers
  - `Data/AuthDbContext.cs`: ASP.NET Identity + refresh token persistence
  - `Data/UserRepository.cs`: Parameterized database query sample
  - `Models/User.cs`: Legacy user model
  - `Models/ApplicationUser.cs`: ASP.NET Identity user model
  - `Models/AuthContracts.cs`: Auth request/response contracts
- `tests/SafeVault.Tests`: NUnit security tests
  - `TestInputValidation.cs`: XSS and input validation tests
  - `TestParameterizedQueries.cs`: SQL injection resistance tests
  - `TestLoginSecurity.cs`: Secure login and credential verification tests
  - `TestIdentityAuthApi.cs`: registration/login/JWT refresh/role endpoint tests
  - `TestSecurityHeaders.cs`: CSP and security header validation tests
- `web/webform.html`: Secure sample web form
- `database/database.sql`: Base user table schema

## Modular Design

- `Security` isolates authentication, hashing, sanitization, and validation concerns.
- `Security` isolates authentication, hashing, sanitization, validation, and role authorization concerns.
- `Data` contains database access logic only.
- `Helpers` contains generic reusable utilities.
- `Models` contains transport/domain objects used across modules.

This separation keeps components focused, easier to test, and safer to evolve.

## Naming Conventions

- `PascalCase` for class names, public methods, and properties.
- Verb-first method names for behavior (`ValidateAndNormalizeEmail`, `LoginUser`).
- Clear, security-specific names for intent (`PasswordHash`, `PasswordSalt`, `ContainsPotentialXss`).
- Test method names follow `Method_Condition_ExpectedResult` style where practical.

## Documentation Conventions

- Public APIs include XML documentation comments.
- Security-critical sections include concise inline comments explaining intent.
- Keep comments focused on *why* and constraints, not obvious syntax.
- XML docs are generated during build via `GenerateDocumentationFile`.

## Prerequisites

- .NET SDK 8.0+

## Build

```bash
dotnet build SafeVault.sln
```

## Run Web App

```bash
dotnet dev-certs https --trust
dotnet run --project src/SafeVault/SafeVault.csproj --urls https://localhost:7181
```

Open the MVC page:

- `https://localhost:7181/`

Demo credentials:

- `admin / Admin#123!` (Admin role)
- `user / User#123!` (User role)
- `guest / Guest#123!` (Guest role)

Minimal API endpoints:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `GET /api/admin/dashboard` (Bearer token, Admin policy)
- `GET /api/user/profile` (Bearer token, UserOrAdmin policy)
- `GET /api/guest/welcome` (Bearer token, Guest policy)

Swagger UI:

- `https://localhost:7181/swagger/index.html`
- Use `POST /api/auth/login` to obtain an access token, then click **Authorize** and paste: `Bearer <access_token>`

## Run Tests

```bash
dotnet test SafeVault.sln
```

## What Is Covered

- Username validation with strict allowlist (`A-Z`, `a-z`, `0-9`, `_`, `.`, `-`) and lowercase normalization
- Email normalization and format validation
- Content Security Policy (CSP) headers to prevent inline script execution
- Security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
- CORS configuration with explicit origin allowlist
- Output encoding for HTML rendering to reduce XSS risk
- Detection and cleanup helpers for common XSS payload patterns
- Parameterized query usage to block SQL injection payloads
- ASP.NET Identity password hashing/salting for registered users
- JWT bearer authentication with short-lived access tokens and refresh tokens
- Role-based authorization rules and policies (`Admin`, `User`, `Guest`)
- HTTPS redirection with permanent redirects, HSTS, and proxy-aware forwarded header handling
- Auth and access event logging for login and protected endpoint usage
- Unit tests simulating SQL injection and XSS attack scenarios
- Unit tests validating invalid login and unauthorized role access scenarios
