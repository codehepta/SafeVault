using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

/// <summary>
/// View model for MVC registration form input and result messages.
/// </summary>
public class RegisterPageViewModel
{
    /// <summary>
    /// Gets or sets submitted username.
    /// </summary>
    [Required]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets submitted email.
    /// </summary>
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets submitted password.
    /// </summary>
    [Required]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets user-facing registration result message.
    /// </summary>
    public string? Message { get; set; }
}