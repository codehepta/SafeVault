using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace SafeVault.Middleware;

/// <summary>
/// Middleware that adds Content Security Policy (CSP) headers to mitigate XSS attacks
/// by restricting which resources the browser can load.
/// </summary>
public class ContentSecurityPolicyMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Initializes a new instance of the <see cref="ContentSecurityPolicyMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    public ContentSecurityPolicyMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    /// <summary>
    /// Processes the HTTP request and adds CSP headers.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        // Default strict CSP policy that prevents inline scripts and restricts resource loading
        var cspPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
        
        // Add Content-Security-Policy header
        context.Response.Headers["Content-Security-Policy"] = cspPolicy;
        
        // Also add X-Content-Type-Options to prevent MIME sniffing
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        
        // Add X-Frame-Options for additional clickjacking protection
        context.Response.Headers["X-Frame-Options"] = "DENY";
        
        // Add X-XSS-Protection (deprecated but still good for legacy browsers)
        context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        
        await _next(context);
    }
}

/// <summary>
/// Extension methods for registering CSP middleware.
/// </summary>
public static class ContentSecurityPolicyMiddlewareExtensions
{
    /// <summary>
    /// Adds Content Security Policy middleware to the application pipeline.
    /// </summary>
    /// <param name="builder">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    public static IApplicationBuilder UseContentSecurityPolicy(
        this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ContentSecurityPolicyMiddleware>();
    }
}
