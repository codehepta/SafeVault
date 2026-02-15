namespace SafeVault.Models;

/// <summary>
/// Represents a persisted refresh token for a user session.
/// </summary>
public class RefreshToken
{
    /// <summary>
    /// Gets or sets unique refresh token identifier.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets identity user id.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets SHA-256 hash of the raw refresh token.
    /// </summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets token expiration time in UTC.
    /// </summary>
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>
    /// Gets or sets token creation time in UTC.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets token revocation time in UTC.
    /// </summary>
    public DateTime? RevokedAtUtc { get; set; }

    /// <summary>
    /// Gets whether token is currently active.
    /// </summary>
    public bool IsActive => RevokedAtUtc is null && DateTime.UtcNow < ExpiresAtUtc;
}
