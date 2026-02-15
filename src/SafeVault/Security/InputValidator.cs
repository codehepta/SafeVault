using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;

namespace SafeVault.Security;

/// <summary>
/// Provides validation and sanitization functions for user-provided input.
/// </summary>
public static class InputValidator
{
    // Input allowlist and high-risk XSS patterns used for quick server-side checks.
    private static readonly Regex AllowedUsernamePattern = new("^[a-zA-Z0-9_.-]{3,50}$", RegexOptions.Compiled);
    private static readonly Regex ScriptTagPattern = new("<\\s*script[^>]*>.*?<\\s*/\\s*script\\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex EventHandlerPattern = new("on[a-z]+\\s*=\\s*(([\"']).*?\\2|[^\\s>]+)", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex JavascriptProtocolPattern = new("javascript\\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex InlineIframePattern = new("<\\s*iframe[^>]*>.*?<\\s*/\\s*iframe\\s*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex IframeTagPattern = new("<\\s*/?\\s*iframe[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex SrcDocPattern = new("srcdoc\\s*=\\s*(([\"']).*?\\2|[^\\s>]+)", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>
    /// Validates and normalizes a username according to the SafeVault allowlist policy.
    /// Usernames are normalized to lowercase to prevent case-sensitive duplicates.
    /// </summary>
    /// <param name="username">Username input from client.</param>
    /// <returns>Trimmed and lowercase-normalized username when valid.</returns>
    /// <exception cref="ArgumentException">Thrown when the username is missing or invalid.</exception>
    public static string ValidateAndSanitizeUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username is required.", nameof(username));
        }

        var trimmed = username.Trim();
        if (!AllowedUsernamePattern.IsMatch(trimmed))
        {
            throw new ArgumentException("Username contains invalid characters.", nameof(username));
        }

        // Normalize to lowercase to prevent duplicate accounts with different casing
        return trimmed.ToLowerInvariant();
    }

    /// <summary>
    /// Validates and normalizes an email address.
    /// </summary>
    /// <param name="email">Email input from client.</param>
    /// <returns>Normalized lowercase email.</returns>
    /// <exception cref="ArgumentException">Thrown when email is missing or malformed.</exception>
    public static string ValidateAndNormalizeEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ArgumentException("Email is required.", nameof(email));
        }

        var trimmed = email.Trim();
        var parsed = new MailAddress(trimmed);

        if (!string.Equals(parsed.Address, trimmed, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Email format is invalid.", nameof(email));
        }

        return parsed.Address.ToLowerInvariant();
    }

    /// <summary>
    /// Encodes a value for safe rendering in HTML contexts.
    /// </summary>
    /// <param name="input">Raw input value.</param>
    /// <returns>HTML-encoded safe output.</returns>
    public static string SanitizeForHtml(string input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        return WebUtility.HtmlEncode(input.Trim());
    }

    /// <summary>
    /// Detects likely XSS patterns in a string.
    /// </summary>
    /// <param name="input">Raw input value.</param>
    /// <returns><c>true</c> when suspicious XSS indicators are present.</returns>
    public static bool ContainsPotentialXss(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        return ScriptTagPattern.IsMatch(input)
               || EventHandlerPattern.IsMatch(input)
               || JavascriptProtocolPattern.IsMatch(input)
             || InlineIframePattern.IsMatch(input)
             || SrcDocPattern.IsMatch(input);
    }

    /// <summary>
    /// Removes common XSS payload patterns from the input.
    /// </summary>
    /// <param name="input">Raw input value.</param>
    /// <returns>Cleaned input with dangerous fragments removed.</returns>
    public static string RemoveXssAttempts(string input)
    {
        if (input is null)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var cleaned = ScriptTagPattern.Replace(input, string.Empty);
        cleaned = InlineIframePattern.Replace(cleaned, string.Empty);
        cleaned = IframeTagPattern.Replace(cleaned, string.Empty);
        cleaned = EventHandlerPattern.Replace(cleaned, string.Empty);
        cleaned = JavascriptProtocolPattern.Replace(cleaned, string.Empty);
        cleaned = SrcDocPattern.Replace(cleaned, string.Empty);

        return cleaned.Trim();
    }
}