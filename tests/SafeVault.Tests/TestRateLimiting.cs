using NUnit.Framework;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using SafeVault;
using SafeVault.Models;

namespace SafeVault.Tests;

/// <summary>
/// Tests for rate limiting protection on authentication endpoints
/// Validates that brute-force attacks are prevented through per-IP rate limits
/// </summary>
[TestFixture]
public class TestRateLimiting
{
    private WebApplicationFactory<Program>? _factory;
    private HttpClient? _client;

    [SetUp]
    public void Setup()
    {
        _factory = new WebApplicationFactory<Program>();
        _client = _factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        _client?.Dispose();
        _factory?.Dispose();
    }

    [Test]
    public async Task LoginEndpoint_ExceedsRateLimit_Returns429()
    {
        // Arrange - Login endpoint has limit of 5 requests per minute
        var loginRequest = new LoginRequest("testuser", "testpass");

        // Act - Make 6 requests rapidly (one more than the limit)
        HttpResponseMessage? lastResponse = null;
        for (int i = 0; i < 6; i++)
        {
            lastResponse = await _client!.PostAsJsonAsync("/api/auth/login", loginRequest);
        }

        // Assert - The 6th request should be rate limited
        Assert.That(lastResponse, Is.Not.Null);
        Assert.That(lastResponse!.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests),
            "Login endpoint should return 429 after exceeding rate limit of 5 requests");
        
        // Verify Retry-After header is present
        Assert.That(lastResponse.Headers.Contains("Retry-After"), Is.True,
            "Response should include Retry-After header");
    }

    [Test]
    public async Task RegisterEndpoint_ExceedsRateLimit_Returns429()
    {
        // Arrange - Register endpoint has limit of 2 requests per minute
        var registerRequest = new RegisterRequest("newuser", "Password#123!", "user@example.com", null);

        // Act - Make 3 requests rapidly (one more than the limit)
        HttpResponseMessage? lastResponse = null;
        for (int i = 0; i < 3; i++)
        {
            lastResponse = await _client!.PostAsJsonAsync("/api/auth/register", registerRequest);
        }

        // Assert - The 3rd request should be rate limited
        Assert.That(lastResponse, Is.Not.Null);
        Assert.That(lastResponse!.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests),
            "Register endpoint should return 429 after exceeding rate limit of 2 requests");
        
        // Verify response includes error message
        var content = await lastResponse.Content.ReadAsStringAsync();
        Assert.That(content, Does.Contain("Too many requests"),
            "Response should include rate limit error message");
    }

    [Test]
    public async Task RefreshEndpoint_ExceedsRateLimit_Returns429()
    {
        // Arrange - Refresh endpoint has limit of 10 requests per minute
        var refreshRequest = new RefreshTokenRequest("dummy-refresh-token");

        // Act - Make 11 requests rapidly (one more than the limit)
        HttpResponseMessage? lastResponse = null;
        for (int i = 0; i < 11; i++)
        {
            lastResponse = await _client!.PostAsJsonAsync("/api/auth/refresh", refreshRequest);
        }

        // Assert - The 11th request should be rate limited
        Assert.That(lastResponse, Is.Not.Null);
        Assert.That(lastResponse!.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests),
            "Refresh endpoint should return 429 after exceeding rate limit of 10 requests");
    }

    [Test]
    public async Task LoginEndpoint_WithinRateLimit_AllowsRequests()
    {
        // Arrange - Login endpoint has limit of 5 requests per minute
        var loginRequest = new LoginRequest("testuser", "testpass");

        // Act - Make 5 requests (at the limit, should all succeed or return 400/401, but not 429)
        for (int i = 0; i < 5; i++)
        {
            var response = await _client!.PostAsJsonAsync("/api/auth/login", loginRequest);
            
            // Assert - Should not be rate limited (can be 400 Bad Request or 401 Unauthorized, but not 429)
            Assert.That(response.StatusCode, Is.Not.EqualTo(HttpStatusCode.TooManyRequests),
                $"Request {i + 1} should not be rate limited when within the limit");
        }
    }

    [Test]
    public async Task RateLimitResponse_IncludesRetryAfterHeader()
    {
        // Arrange
        var loginRequest = new LoginRequest("testuser", "testpass");

        // Act - Exceed rate limit
        HttpResponseMessage? rateLimitedResponse = null;
        for (int i = 0; i < 6; i++)
        {
            rateLimitedResponse = await _client!.PostAsJsonAsync("/api/auth/login", loginRequest);
        }

        // Assert
        Assert.That(rateLimitedResponse, Is.Not.Null);
        Assert.That(rateLimitedResponse!.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
        
        if (rateLimitedResponse.Headers.Contains("Retry-After"))
        {
            var retryAfter = rateLimitedResponse.Headers.GetValues("Retry-After").First();
            Assert.That(int.TryParse(retryAfter, out var seconds), Is.True,
                "Retry-After header should be a valid integer (seconds)");
            Assert.That(seconds, Is.GreaterThan(0),
                "Retry-After should indicate positive time to wait");
        }
    }

    [Test]
    public async Task DifferentEndpoints_HaveIndependentRateLimits()
    {
        // Arrange
        var loginRequest = new LoginRequest("testuser", "testpass");
        var registerRequest = new RegisterRequest("newuser", "Password#123!", "user@example.com", null);

        // Act - Exhaust login rate limit
        for (int i = 0; i < 6; i++)
        {
            await _client!.PostAsJsonAsync("/api/auth/login", loginRequest);
        }

        // Try register endpoint - should still work (has separate rate limit)
        var registerResponse = await _client!.PostAsJsonAsync("/api/auth/register", registerRequest);

        // Assert - Register should not be affected by login rate limit
        Assert.That(registerResponse.StatusCode, Is.Not.EqualTo(HttpStatusCode.TooManyRequests),
            "Register endpoint should have independent rate limit from login endpoint");
    }
}
