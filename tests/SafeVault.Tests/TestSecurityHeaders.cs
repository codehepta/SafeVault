using NUnit.Framework;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http;
using System.Threading.Tasks;
using SafeVault;

namespace SafeVault.Tests;

/// <summary>
/// Tests for security headers middleware (CSP, X-Frame-Options, etc.)
/// </summary>
[TestFixture]
public class TestSecurityHeaders
{
    private HttpClient? _client;

    [SetUp]
    public void Setup()
    {
        var factory = new WebApplicationFactory<Program>();
        _client = factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        _client?.Dispose();
    }

    [Test]
    public async Task HomePage_IncludesContentSecurityPolicyHeader()
    {
        // Arrange & Act
        var response = await _client!.GetAsync("/");

        // Assert
        Assert.IsTrue(response.Headers.Contains("Content-Security-Policy"),
            "Content-Security-Policy header should be present");
        
        var cspHeader = response.Headers.GetValues("Content-Security-Policy");
        var cspValue = string.Join(";", cspHeader);
        
        // Verify strict CSP policy
        Assert.That(cspValue, Does.Contain("default-src 'self'"),
            "CSP should restrict default sources to same origin");
        Assert.That(cspValue, Does.Contain("script-src 'self'"),
            "CSP should only allow scripts from same origin");
        Assert.That(cspValue, Does.Contain("frame-ancestors 'none'"),
            "CSP should prevent framing");
    }

    [Test]
    public async Task HomePage_IncludesXFrameOptionsHeader()
    {
        // Arrange & Act
        var response = await _client!.GetAsync("/");

        // Assert
        Assert.IsTrue(response.Headers.Contains("X-Frame-Options"),
            "X-Frame-Options header should be present");
        
        var headerValue = response.Headers.GetValues("X-Frame-Options");
        Assert.That(string.Join("", headerValue), Is.EqualTo("DENY"),
            "X-Frame-Options should be set to DENY to prevent clickjacking");
    }

    [Test]
    public async Task HomePage_IncludesXContentTypeOptionsHeader()
    {
        // Arrange & Act
        var response = await _client!.GetAsync("/");

        // Assert
        Assert.IsTrue(response.Headers.Contains("X-Content-Type-Options"),
            "X-Content-Type-Options header should be present");
        
        var headerValue = response.Headers.GetValues("X-Content-Type-Options");
        Assert.That(string.Join("", headerValue), Is.EqualTo("nosniff"),
            "X-Content-Type-Options should be set to nosniff");
    }

    [Test]
    public async Task HomePage_IncludesXXSSProtectionHeader()
    {
        // Arrange & Act
        var response = await _client!.GetAsync("/");

        // Assert
        Assert.IsTrue(response.Headers.Contains("X-XSS-Protection"),
            "X-XSS-Protection header should be present");
        
        var headerValue = response.Headers.GetValues("X-XSS-Protection");
        Assert.That(string.Join("", headerValue), Does.Contain("1"),
            "X-XSS-Protection should be enabled");
    }

    [Test]
    public async Task ApiEndpoint_IncludesSecurityHeaders()
    {
        // Arrange & Act
        var response = await _client!.GetAsync("/api/auth/login");

        // Assert
        // Even though this will return 405 (Method Not Allowed), headers should still be present
        Assert.IsTrue(response.Headers.Contains("Content-Security-Policy"),
            "API endpoints should also include CSP header");
        Assert.IsTrue(response.Headers.Contains("X-Frame-Options"),
            "API endpoints should also include X-Frame-Options");
        Assert.IsTrue(response.Headers.Contains("X-Content-Type-Options"),
            "API endpoints should also include X-Content-Type-Options");
    }
}
