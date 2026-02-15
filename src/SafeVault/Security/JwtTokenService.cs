using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Models;

namespace SafeVault.Security;

/// <summary>
/// Configuration values for JWT and refresh tokens.
/// </summary>
public sealed class JwtOptions
{
    /// <summary>
    /// Configuration section name used for JWT settings.
    /// </summary>
    public const string SectionName = "Jwt";

    /// <summary>
    /// Expected token issuer.
    /// </summary>
    public string Issuer { get; set; } = "SafeVault";

    /// <summary>
    /// Expected token audience.
    /// </summary>
    public string Audience { get; set; } = "SafeVault.Client";

    /// <summary>
    /// Symmetric signing key used for access token signatures.
    /// </summary>
    public string SigningKey { get; set; } = "SafeVault_Dev_Only_Super_Long_Key_Change_In_Production_12345";

    /// <summary>
    /// Access token lifetime in minutes.
    /// </summary>
    public int AccessTokenMinutes { get; set; } = 5;

    /// <summary>
    /// Refresh token lifetime in days.
    /// </summary>
    public int RefreshTokenDays { get; set; } = 1;
}

/// <summary>
/// Handles issuing and validating JWT access tokens and refresh token material.
/// </summary>
public class JwtTokenService
{
    private readonly JwtOptions _options;

    /// <summary>
    /// Initializes a new JWT token service.
    /// </summary>
    /// <param name="options">JWT configuration options.</param>
    public JwtTokenService(IOptions<JwtOptions> options)
    {
        _options = options.Value;
    }

    /// <summary>
    /// Creates a short-lived JWT access token for a user and role.
    /// </summary>
    public (string Token, DateTime ExpiresAtUtc) CreateAccessToken(ApplicationUser user, string role)
    {
        var expiresAtUtc = DateTime.UtcNow.AddMinutes(_options.AccessTokenMinutes);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.Role, role)
        };

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expiresAtUtc,
            signingCredentials: creds);

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAtUtc);
    }

    /// <summary>
    /// Generates a cryptographically secure refresh token.
    /// </summary>
    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Produces SHA-256 hash for token-at-rest storage.
    /// </summary>
    public static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes);
    }

    /// <summary>
    /// Builds token validation parameters for JWT bearer middleware.
    /// </summary>
    public TokenValidationParameters BuildValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _options.Issuer,
            ValidAudience = _options.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey)),
            ClockSkew = TimeSpan.Zero
        };
    }

    /// <summary>
    /// Gets refresh token expiration for newly minted refresh tokens.
    /// </summary>
    public DateTime GetRefreshTokenExpiryUtc()
    {
        return DateTime.UtcNow.AddDays(_options.RefreshTokenDays);
    }
}
