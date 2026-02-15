using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

/// <summary>
/// View model for MVC login form input and result messages.
/// </summary>
public class LoginPageViewModel
{
    /// <summary>
    /// Gets or sets submitted username.
    /// </summary>
    [Required]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets submitted password.
    /// </summary>
    [Required]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets user-facing login result message.
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Gets or sets resolved role for display after successful login.
    /// </summary>
    public string? Role { get; set; }
}
