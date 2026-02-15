using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestIdentityAuthApi
{
    [Test]
    public async Task RegisterAndLogin_ReturnsJwtAndRefreshToken()
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        var register = await client.PostAsJsonAsync("/api/auth/register", new
        {
            Username = "apitestuser",
            Password = "ApiTest#123",
            Email = "apitestuser@example.com",
            Role = "User"
        });

        Assert.That(register.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        var login = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "apitestuser",
            Password = "ApiTest#123"
        });

        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var tokenResponse = await login.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(tokenResponse, Is.Not.Null);
        Assert.That(tokenResponse!.AccessToken, Is.Not.Empty);
        Assert.That(tokenResponse.RefreshToken, Is.Not.Empty);
    }

    [Test]
    public async Task RefreshToken_ReturnsNewTokenPair()
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        await client.PostAsJsonAsync("/api/auth/register", new
        {
            Username = "refreshuser",
            Password = "Refresh#123",
            Email = "refreshuser@example.com",
            Role = "User"
        });

        var login = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "refreshuser",
            Password = "Refresh#123"
        });

        var tokenResponse = await login.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(tokenResponse, Is.Not.Null);

        var refresh = await client.PostAsJsonAsync("/api/auth/refresh", new
        {
            RefreshToken = tokenResponse!.RefreshToken
        });

        Assert.That(refresh.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var refreshed = await refresh.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(refreshed, Is.Not.Null);
        Assert.That(refreshed!.RefreshToken, Is.Not.EqualTo(tokenResponse.RefreshToken));
    }

    [Test]
    public async Task AdminEndpoint_UserRoleForbidden_AdminRoleAllowed()
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        var userLogin = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "user",
            Password = "User#123!"
        });
        var userTokens = await userLogin.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(userTokens, Is.Not.Null);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userTokens!.AccessToken);
        var forbidden = await client.GetAsync("/api/admin/dashboard");
        Assert.That(forbidden.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));

        var adminLogin = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "admin",
            Password = "Admin#123!"
        });
        var adminTokens = await adminLogin.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(adminTokens, Is.Not.Null);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminTokens!.AccessToken);
        var allowed = await client.GetAsync("/api/admin/dashboard");
        Assert.That(allowed.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Register_WithAdminRoleRequest_AssignsUserRoleOnly()
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        var register = await client.PostAsJsonAsync("/api/auth/register", new
        {
            Username = "roleescalation",
            Password = "RoleEsc#123",
            Email = "roleescalation@example.com",
            Role = "Admin"
        });

        Assert.That(register.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        var login = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "roleescalation",
            Password = "RoleEsc#123"
        });

        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var tokens = await login.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.That(tokens, Is.Not.Null);
        Assert.That(tokens!.Role, Is.EqualTo("User"));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var adminAttempt = await client.GetAsync("/api/admin/dashboard");
        Assert.That(adminAttempt.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Login_WithSqlInjectionPayload_IsRejected()
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        var login = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "' OR 1=1 --",
            Password = "AnyPass#123"
        });

        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Register_WithXssPayload_IsRejected()
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        var register = await client.PostAsJsonAsync("/api/auth/register", new
        {
            Username = "<script>alert(1)</script>",
            Password = "ValidPass#123",
            Email = "xss@example.com",
            Role = "User"
        });

        Assert.That(register.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Login_WithXssPasswordPayload_IsRejected()
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        var login = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "admin",
            Password = "<script>alert(1)</script>"
        });

        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCase("<script>alert(1)</script>")]
    [TestCase("javascript:alert(1)")]
    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("<iframe srcdoc=<script>alert(1)</script>>")]
    public async Task Login_WithMaliciousPasswordPayloadMatrix_IsRejected(string maliciousPassword)
    {
        await using var factory = new SafeVaultApiFactory();
        using var client = CreateHttpsClient(factory);

        var login = await client.PostAsJsonAsync("/api/auth/login", new
        {
            Username = "admin",
            Password = maliciousPassword
        });

        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    private sealed class SafeVaultApiFactory : WebApplicationFactory<Program>
    {
        private readonly string _databaseName = $"auth-tests-{Guid.NewGuid()}";

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureServices(services =>
            {
                var dbContextDescriptor = services.SingleOrDefault(descriptor =>
                    descriptor.ServiceType == typeof(DbContextOptions<AuthDbContext>));

                if (dbContextDescriptor is not null)
                {
                    services.Remove(dbContextDescriptor);
                }

                services.AddDbContext<AuthDbContext>(options =>
                    options.UseInMemoryDatabase(_databaseName));

                var provider = services.BuildServiceProvider();
                using var scope = provider.CreateScope();

                var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                dbContext.Database.EnsureCreated();

                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                IdentitySeeder.SeedAsync(roleManager, userManager).GetAwaiter().GetResult();
            });
        }
    }

    private static HttpClient CreateHttpsClient(SafeVaultApiFactory factory)
    {
        return factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
    }
}
