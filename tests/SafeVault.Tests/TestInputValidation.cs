using NUnit.Framework;
using SafeVault.Helpers;
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void IsValidInput_AllowsLettersDigitsAndConfiguredSpecialCharacters()
    {
        var isValid = ValidationHelpers.IsValidInput("User123@#$", "@#$");

        Assert.That(isValid, Is.True);
    }

    [Test]
    public void IsValidInput_RejectsCharactersOutsideAllowedSet()
    {
        var isValid = ValidationHelpers.IsValidInput("User123!", "@#$");

        Assert.That(isValid, Is.False);
    }

    [Test]
    public void IsValidInput_RejectsNullOrEmpty()
    {
        Assert.That(ValidationHelpers.IsValidInput(string.Empty, "@#$"), Is.False);
        Assert.That(ValidationHelpers.IsValidInput(null!, "@#$"), Is.False);
    }

    [Test]
    public void TestForSQLInjection()
    {
        const string payload = "' OR 1=1 --";

        Assert.Throws<ArgumentException>(() => InputValidator.ValidateAndSanitizeUsername(payload));
    }

    [Test]
    public void TestForXSS()
    {
        const string payload = "<script>alert('xss')</script>";

        var sanitized = InputValidator.SanitizeForHtml(payload);

        Assert.That(sanitized, Does.Not.Contain("<script>"));
        Assert.That(sanitized, Does.Contain("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"));
    }

    [Test]
    public void ContainsPotentialXss_ReturnsTrueForMaliciousPayloads()
    {
        Assert.That(InputValidator.ContainsPotentialXss("<script>alert('xss')</script>"), Is.True);
        Assert.That(InputValidator.ContainsPotentialXss("<img src=x onerror='alert(1)'>"), Is.True);
        Assert.That(InputValidator.ContainsPotentialXss("<img src=x onerror=alert(1)>"), Is.True);
        Assert.That(InputValidator.ContainsPotentialXss("<iframe srcdoc=<script>alert(1)</script>>"), Is.True);
        Assert.That(InputValidator.ContainsPotentialXss("javascript:alert(1)"), Is.True);
    }

    [Test]
    public void RemoveXssAttempts_RemovesMaliciousMarkup()
    {
        const string payload = "<script>alert(1)</script>Hello <img src=x onerror=alert(1)> javascript:alert(2) <iframe srcdoc=<script>alert(3)</script>>";

        var cleaned = InputValidator.RemoveXssAttempts(payload);

        Assert.That(cleaned, Does.Not.Contain("<script"));
        Assert.That(cleaned, Does.Not.Contain("onerror="));
        Assert.That(cleaned, Does.Not.Contain("javascript:"));
        Assert.That(cleaned, Does.Not.Contain("srcdoc="));
        Assert.That(cleaned, Does.Contain("Hello"));
    }

    [Test]
    public void ValidUsernameAndEmail_AreAccepted()
    {
        var username = InputValidator.ValidateAndSanitizeUsername("safe_user-1");
        var email = InputValidator.ValidateAndNormalizeEmail("person@example.com");

        Assert.That(username, Is.EqualTo("safe_user-1"));
        Assert.That(email, Is.EqualTo("person@example.com"));
    }
}