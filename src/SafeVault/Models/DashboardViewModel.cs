namespace SafeVault.Models;

/// <summary>
/// View model for the dashboard and per-user password vault listing.
/// </summary>
public class DashboardViewModel
{
    /// <summary>
    /// Gets or sets the signed-in username.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the resolved user role.
    /// </summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a user-facing status message.
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Gets or sets password entries for the current user.
    /// </summary>
    public IReadOnlyList<PasswordEntryViewModel> PasswordEntries { get; set; } = Array.Empty<PasswordEntryViewModel>();
}

/// <summary>
/// View model for an individual password entry row.
/// </summary>
public class PasswordEntryViewModel
{
    /// <summary>
    /// Gets or sets entry identifier.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets label for the credential.
    /// </summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets login identifier for the credential.
    /// </summary>
    public string LoginName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets secret as masked preview text.
    /// </summary>
    public string MaskedSecret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets creation timestamp in UTC.
    /// </summary>
    public DateTime CreatedAtUtc { get; set; }
}

/// <summary>
/// View model for admin-only user vault management page.
/// </summary>
public class AdminPanelViewModel
{
    /// <summary>
    /// Gets or sets status message for admin actions.
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Gets or sets all users with vault counts.
    /// </summary>
    public IReadOnlyList<AdminUserVaultViewModel> Users { get; set; } = Array.Empty<AdminUserVaultViewModel>();
}

/// <summary>
/// Represents one user row in the admin panel.
/// </summary>
public class AdminUserVaultViewModel
{
    /// <summary>
    /// Gets or sets identity user id.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets username.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets email.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets role names for the user.
    /// </summary>
    public string Roles { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets number of password entries in user's vault.
    /// </summary>
    public int VaultCount { get; set; }
}

/// <summary>
/// View model for admin user update form.
/// </summary>
public class AdminEditUserViewModel
{
    /// <summary>
    /// Gets or sets user id.
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets username.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets email.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets role.
    /// </summary>
    public string Role { get; set; } = "User";
}