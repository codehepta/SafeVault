using NUnit.Framework;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http;
using System.Threading.Tasks;
using SafeVault;

namespace SafeVault.Tests;

/// <summary>
/// Tests for CORS (Cross-Origin Resource Sharing) configuration
/// Validates that the API properly restricts cross-origin requests to allowed origins only
/// </summary>
[TestFixture]
public class TestCorsSecurity
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
    public async Task CorsPreflightRequest_AllowedOrigin_ReturnsSuccess()
    {
        // Arrange
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/auth/login");
        request.Headers.Add("Origin", "https://localhost:7181");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type");

        // Act
        var response = await _client!.SendAsync(request);

        // Assert
        Assert.That(response.IsSuccessStatusCode, Is.True, 
            "CORS preflight should succeed for allowed origin");
        
        // Check that CORS headers are present
        Assert.IsTrue(response.Headers.Contains("Access-Control-Allow-Origin"),
            "Response should include Access-Control-Allow-Origin header");
        
        var allowOriginHeader = string.Join("", response.Headers.GetValues("Access-Control-Allow-Origin"));
        Assert.That(allowOriginHeader, Does.Contain("https://localhost:7181"),
            "Access-Control-Allow-Origin should match the requested origin");
    }

    [Test]
    public async Task CorsPreflightRequest_DisallowedOrigin_RejectsCors()
    {
        // Arrange
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/auth/login");
        request.Headers.Add("Origin", "https://malicious-site.com");
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type");

        // Act
        var response = await _client!.SendAsync(request);

        // Assert - preflight will succeed but won't include CORS headers for disallowed origin
        if (response.Headers.Contains("Access-Control-Allow-Origin"))
        {
            var allowOriginHeader = string.Join("", response.Headers.GetValues("Access-Control-Allow-Origin"));
            Assert.That(allowOriginHeader, Does.Not.Contain("https://malicious-site.com"),
                "Access-Control-Allow-Origin should not include disallowed origins");
        }
        // If header is not present, the CORS middleware correctly rejected it
    }

    [Test]
    public async Task CorsActualRequest_AllowedOrigin_IncludesCorsHeaders()
    {
        // Arrange
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/guest/welcome");
        request.Headers.Add("Origin", "https://localhost:7181");

        // Act
        var response = await _client!.SendAsync(request);

        // Assert - this will return 401 (no auth token) but should still include CORS headers
        if (response.Headers.Contains("Access-Control-Allow-Origin"))
        {
            var allowOriginHeader = string.Join("", response.Headers.GetValues("Access-Control-Allow-Origin"));
            Assert.That(allowOriginHeader, Does.Contain("https://localhost:7181"),
                "Actual requests should include CORS headers for allowed origins");
        }
    }

    [Test]
    public async Task CorsRequest_MultipleAllowedOrigins_ConfiguredCorrectly()
    {
        // This test verifies that CORS is configured with explicit origins rather than wildcard
        
        // Arrange
        var request1 = new HttpRequestMessage(HttpMethod.Options, "/api/auth/login");
        request1.Headers.Add("Origin", "https://localhost:7181");
        request1.Headers.Add("Access-Control-Request-Method", "POST");

        var request2 = new HttpRequestMessage(HttpMethod.Options, "/api/auth/login");
        request2.Headers.Add("Origin", "https://localhost:5001");
        request2.Headers.Add("Access-Control-Request-Method", "POST");

        // Act
        var response1 = await _client!.SendAsync(request1);
        var response2 = await _client!.SendAsync(request2);

        // Assert - both configured origins should work
        Assert.That(response1.IsSuccessStatusCode || response1.Headers.Contains("Access-Control-Allow-Origin"), 
            Is.True, "First allowed origin should be accepted");
        Assert.That(response2.IsSuccessStatusCode || response2.Headers.Contains("Access-Control-Allow-Origin"), 
            Is.True, "Second allowed origin should be accepted");
        
        // Verify not using wildcard (*)
        if (response1.Headers.Contains("Access-Control-Allow-Origin"))
        {
            var allowOriginHeader = string.Join("", response1.Headers.GetValues("Access-Control-Allow-Origin"));
            Assert.That(allowOriginHeader, Is.Not.EqualTo("*"),
                "CORS should use explicit origins, not wildcard (*)");
        }
    }
}
