using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using SafeVault.Helpers;
using SafeVault.Models;
using SafeVault.Data;
using SafeVault.Security;
using SafeVault.Middleware;

var builder = WebApplication.CreateBuilder(args);

if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")))
{
    builder.WebHost.UseUrls("https://localhost:7181");
}

builder.Services.AddControllersWithViews();
builder.Services.AddLogging();

// Configure CORS with secure defaults
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
            ?? new[] { "https://localhost:7181" };
        
        policy.WithOrigins(allowedOrigins)
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Configure rate limiting to prevent brute-force attacks
builder.Services.AddRateLimiter(options =>
{
    // Rate limit for login endpoint: 5 requests per minute per IP
    options.AddPolicy("login", context =>
        System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    // Rate limit for registration endpoint: 2 requests per minute per IP
    options.AddPolicy("register", context =>
        System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 2,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    // Rate limit for refresh token endpoint: 10 requests per minute per IP
    options.AddPolicy("refresh", context =>
        System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }));

    // Global rate limit for all other endpoints: 100 requests per minute per IP
    options.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        // Use IP address as the partition key
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        
        return System.Threading.RateLimiting.RateLimitPartition.GetFixedWindowLimiter(
            ipAddress,
            _ => new System.Threading.RateLimiting.FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            });
    });

    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        
        if (context.Lease.TryGetMetadata(System.Threading.RateLimiting.MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
        }

        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "Too many requests. Please try again later.",
            retryAfter = retryAfter.TotalSeconds
        }, cancellationToken);
    };
});
builder.Services.AddHttpsRedirection(options =>
{
    options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
});
builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SafeVault API",
        Version = "v1"
    });

    var jwtSecurityScheme = new OpenApiSecurityScheme
    {
        Scheme = "bearer",
        BearerFormat = "JWT",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Description = "JWT Bearer token. Example: Bearer {token}",
        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };

    options.AddSecurityDefinition(jwtSecurityScheme.Reference.Id, jwtSecurityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [jwtSecurityScheme] = Array.Empty<string>()
    });
});

const string DefaultDevKey = "SafeVault_Dev_Only_Super_Long_Key_Change_In_Production_12345";

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));
builder.Services.PostConfigure<JwtOptions>(options =>
{
    bool isProduction = !builder.Environment.IsDevelopment() && builder.Environment.EnvironmentName != "Testing";
    
    if (string.IsNullOrWhiteSpace(options.SigningKey) || options.SigningKey.Length < 32)
    {
        // In production, REJECT weak or default keys - fail fast
        if (isProduction)
        {
            throw new InvalidOperationException(
                "CRITICAL SECURITY ERROR: JWT signing key is missing or too weak for production. " +
                "Set JWT:SigningKey (minimum 32 characters) in appsettings.Production.json or via JWT__SigningKey environment variable. " +
                "Generate a secure key with: openssl rand -base64 48");
        }
        
        // In development/testing, use default key but warn
        options.SigningKey = DefaultDevKey;
        Console.WriteLine("WARNING: Using default development JWT signing key. Do not use in production!");
    }
    else if (options.SigningKey == DefaultDevKey && isProduction)
    {
        // Explicitly reject the known default key in production
        throw new InvalidOperationException(
            "CRITICAL SECURITY ERROR: Default development JWT signing key detected in production. " +
            "This is a severe security vulnerability. Generate and configure a unique production key.");
    }
});

builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")
                      ?? "Data Source=safevault-auth.db"));

builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 8;
        options.User.RequireUniqueEmail = true;
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddSignInManager<SignInManager<ApplicationUser>>()
    .AddDefaultTokenProviders();

builder.Services.AddScoped<JwtTokenService>();

var issuer = builder.Configuration[$"{JwtOptions.SectionName}:Issuer"] ?? "SafeVault";
var audience = builder.Configuration[$"{JwtOptions.SectionName}:Audience"] ?? "SafeVault.Client";
var signingKey = builder.Configuration[$"{JwtOptions.SectionName}:SigningKey"];

bool isProduction = !builder.Environment.IsDevelopment() && builder.Environment.EnvironmentName != "Testing";

if (string.IsNullOrWhiteSpace(signingKey) || signingKey.Length < 32)
{
    // In production, REJECT weak or default keys - fail fast
    if (isProduction)
    {
        throw new InvalidOperationException(
            "CRITICAL SECURITY ERROR: JWT signing key is missing or too weak for production. " +
            "Set JWT:SigningKey (minimum 32 characters) in appsettings.Production.json or via JWT__SigningKey environment variable. " +
            "Generate a secure key with: openssl rand -base64 48");
    }
    
    // In development/testing, use default key but warn
    signingKey = DefaultDevKey;
    Console.WriteLine("WARNING: Using default development JWT signing key. Do not use in production!");
}
else if (signingKey == DefaultDevKey && isProduction)
{
    // Explicitly reject the known default key in production
    throw new InvalidOperationException(
        "CRITICAL SECURITY ERROR: Default development JWT signing key detected in production. " +
        "This is a severe security vulnerability. Generate and configure a unique production key.");
}

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(jwtOptions =>
    {
        jwtOptions.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(signingKey)),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
    options.AddPolicy("GuestOnly", policy => policy.RequireRole("Guest"));
    options.AddPolicy("UserOrAdmin", policy => policy.RequireRole("User", "Admin"));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await dbContext.Database.EnsureCreatedAsync();

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    await IdentitySeeder.SeedAsync(roleManager, userManager);
}

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseForwardedHeaders();

// Add security headers (CSP, X-Frame-Options, etc.)
app.UseContentSecurityPolicy();

// Enable CORS before authentication
app.UseCors();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Apply rate limiting before authentication
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapPost("/api/auth/login", async (
    [FromBody] LoginRequest request,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    JwtTokenService tokenService,
    AuthDbContext dbContext,
    ILogger<Program> logger) =>
{
    string normalizedUsername;
    try
    {
        normalizedUsername = InputValidator.ValidateAndSanitizeUsername(request.Username);
    }
    catch (ArgumentException)
    {
        logger.LogWarning("Rejected login request due to invalid input format for username {Username}", request.Username);
        return Results.BadRequest(new { Message = "Invalid login payload." });
    }

    if (InputValidator.ContainsPotentialXss(request.Username)
        || InputValidator.ContainsPotentialXss(request.Password)
        || !ValidationHelpers.IsValidInput(request.Password, "!@#$%^&*?"))
    {
        logger.LogWarning("Rejected login request due to potentially malicious content for username {Username}", normalizedUsername);
        return Results.BadRequest(new { Message = "Invalid login payload." });
    }

    var user = await userManager.FindByNameAsync(normalizedUsername);
    if (user is null)
    {
        logger.LogWarning("Login failed for unknown user {Username}", normalizedUsername);
        return Results.Unauthorized();
    }

    var signInResult = await signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
    if (!signInResult.Succeeded)
    {
        logger.LogWarning("Login failed for user {Username}", normalizedUsername);
        return Results.Unauthorized();
    }

    var roles = await userManager.GetRolesAsync(user);
    var role = roles.FirstOrDefault() ?? "Guest";
    var (accessToken, accessTokenExpiresAtUtc) = tokenService.CreateAccessToken(user, role);

    var refreshTokenRaw = tokenService.CreateRefreshToken();
    dbContext.RefreshTokens.Add(new RefreshToken
    {
        UserId = user.Id,
        TokenHash = JwtTokenService.HashToken(refreshTokenRaw),
        ExpiresAtUtc = tokenService.GetRefreshTokenExpiryUtc()
    });
    await dbContext.SaveChangesAsync();

    logger.LogInformation("User {Username} logged in successfully", normalizedUsername);

    return Results.Ok(new TokenResponse(accessToken, refreshTokenRaw, accessTokenExpiresAtUtc, role));
})
.RequireRateLimiting("login");

app.MapPost("/api/auth/register", async (
    [FromBody] RegisterRequest request,
    UserManager<ApplicationUser> userManager,
    ILogger<Program> logger) =>
{
    string normalizedUsername;
    string normalizedEmail;
    try
    {
        normalizedUsername = InputValidator.ValidateAndSanitizeUsername(request.Username);
        normalizedEmail = InputValidator.ValidateAndNormalizeEmail(request.Email);
    }
    catch (ArgumentException)
    {
        logger.LogWarning("Registration blocked due to invalid input for user {Username}", request.Username);
        return Results.BadRequest(new { Message = "Invalid registration payload." });
    }

    const string role = "User";

    var user = new ApplicationUser
    {
        UserName = normalizedUsername,
        Email = normalizedEmail,
        EmailConfirmed = true
    };

    var createResult = await userManager.CreateAsync(user, request.Password);

    if (!createResult.Succeeded)
    {
        logger.LogWarning("Registration failed for user {Username}", normalizedUsername);
        return Results.BadRequest(new
        {
            Message = "Registration failed.",
            Errors = createResult.Errors.Select(error => error.Description)
        });
    }

    await userManager.AddToRoleAsync(user, role);
    logger.LogInformation("User {Username} registered with role {Role}", normalizedUsername, role);

    return Results.Created($"/api/users/{normalizedUsername}", new
    {
        Username = normalizedUsername,
        Role = role
    });
})
.RequireRateLimiting("register");

app.MapPost("/api/auth/refresh", async (
    [FromBody] RefreshTokenRequest request,
    AuthDbContext dbContext,
    UserManager<ApplicationUser> userManager,
    JwtTokenService tokenService,
    ILogger<Program> logger) =>
{
    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        return Results.BadRequest(new { Message = "Refresh token is required." });
    }

    var refreshTokenHash = JwtTokenService.HashToken(request.RefreshToken);
    var persistedRefreshToken = await dbContext.RefreshTokens
        .FirstOrDefaultAsync(token => token.TokenHash == refreshTokenHash);

    if (persistedRefreshToken is null || !persistedRefreshToken.IsActive)
    {
        logger.LogWarning("Refresh token rejected as invalid or inactive");
        return Results.Unauthorized();
    }

    var user = await userManager.FindByIdAsync(persistedRefreshToken.UserId);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    persistedRefreshToken.RevokedAtUtc = DateTime.UtcNow;

    var roles = await userManager.GetRolesAsync(user);
    var role = roles.FirstOrDefault() ?? "Guest";

    var (newAccessToken, accessTokenExpiresAtUtc) = tokenService.CreateAccessToken(user, role);
    var newRefreshTokenRaw = tokenService.CreateRefreshToken();
    dbContext.RefreshTokens.Add(new RefreshToken
    {
        UserId = user.Id,
        TokenHash = JwtTokenService.HashToken(newRefreshTokenRaw),
        ExpiresAtUtc = tokenService.GetRefreshTokenExpiryUtc()
    });

    await dbContext.SaveChangesAsync();
    logger.LogInformation("Refresh token exchanged successfully for user {Username}", user.UserName);
    return Results.Ok(new TokenResponse(newAccessToken, newRefreshTokenRaw, accessTokenExpiresAtUtc, role));
})
.RequireRateLimiting("refresh");

app.MapGet("/api/admin/dashboard", (ClaimsPrincipal principal, ILogger<Program> logger) =>
{
    logger.LogInformation("Admin dashboard access by {Username}", principal.Identity?.Name);
    return Results.Ok(new
    {
        Message = "Welcome to Admin Dashboard",
        User = principal.Identity?.Name ?? string.Empty
    });
})
    .RequireAuthorization("AdminOnly");

app.MapGet("/api/user/profile", (ClaimsPrincipal principal, ILogger<Program> logger) =>
{
    logger.LogInformation("User profile access by {Username}", principal.Identity?.Name);
    return Results.Ok(new { User = principal.Identity?.Name ?? string.Empty });
})
    .RequireAuthorization("UserOrAdmin");

app.MapGet("/api/guest/welcome", (ClaimsPrincipal principal, ILogger<Program> logger) =>
{
    logger.LogInformation("Guest welcome access by {Username}", principal.Identity?.Name);
    return Results.Ok(new { Message = "Guest endpoint access granted." });
})
    .RequireAuthorization("GuestOnly");

app.Run();

/// <summary>
/// Program entry point type exposed for integration testing.
/// </summary>
public partial class Program;
