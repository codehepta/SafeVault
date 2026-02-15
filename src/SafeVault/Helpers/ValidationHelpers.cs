namespace SafeVault.Helpers;

/// <summary>
/// Provides reusable character-level input validation helpers.
/// </summary>
public static class ValidationHelpers
{
    /// <summary>
    /// Checks whether an input contains only letters, digits, and explicitly allowed special characters.
    /// </summary>
    /// <param name="input">Input text to validate.</param>
    /// <param name="allowedSpecialCharacters">Optional set of special characters to allow.</param>
    /// <returns><c>true</c> when all characters are allowed; otherwise <c>false</c>.</returns>
    public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrEmpty(input))
        {
            return false;
        }

        var validCharacters = allowedSpecialCharacters.ToHashSet();
        return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
    }
}