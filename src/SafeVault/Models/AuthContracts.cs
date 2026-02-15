namespace SafeVault.Models;

/// <summary>
/// Registration API request body.
/// </summary>
public sealed record RegisterRequest(string Username, string Password, string Email, string? Role);

/// <summary>
/// Login API request body.
/// </summary>
public sealed record LoginRequest(string Username, string Password);

/// <summary>
/// Refresh token API request body.
/// </summary>
public sealed record RefreshTokenRequest(string RefreshToken);

/// <summary>
/// Token API response.
/// </summary>
public sealed record TokenResponse(string AccessToken, string RefreshToken, DateTime ExpiresAtUtc, string Role);
