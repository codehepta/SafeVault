namespace SafeVault.Models;

/// <summary>
/// Represents a password vault entry owned by an application user.
/// </summary>
public class PasswordEntry
{
    /// <summary>
    /// Gets or sets the primary key.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the owning user id.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the display label for this password entry.
    /// </summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the login username/email for the external service.
    /// </summary>
    public string LoginName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the stored secret value.
    /// </summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets creation timestamp in UTC.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}