namespace SafeVault.Models;

/// <summary>
/// Defines supported application roles.
/// </summary>
public enum UserRole
{
    /// <summary>
    /// Standard application user role.
    /// </summary>
    User,

    /// <summary>
    /// Elevated administrator role.
    /// </summary>
    Admin
}

/// <summary>
/// Represents a SafeVault user record.
/// </summary>
public class User
{
    /// <summary>
    /// Gets or sets the unique user identifier.
    /// </summary>
    public int UserId { get; set; }

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the user's email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the user's role.
    /// </summary>
    public UserRole Role { get; set; } = UserRole.User;
}

/// <summary>
/// Represents an authenticated identity.
/// </summary>
public class AuthenticatedUser
{
    /// <summary>
    /// Gets or sets the authenticated username.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the authenticated role.
    /// </summary>
    public UserRole Role { get; set; } = UserRole.User;
}