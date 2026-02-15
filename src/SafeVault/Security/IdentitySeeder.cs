using Microsoft.AspNetCore.Identity;
using SafeVault.Models;

namespace SafeVault.Security;

/// <summary>
/// Seeds default roles and users required for secure baseline access.
/// </summary>
public static class IdentitySeeder
{
    /// <summary>
    /// Ensures Admin, User, and Guest roles exist and creates baseline accounts.
    /// </summary>
    public static async Task SeedAsync(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
    {
        var roles = new[] { "Admin", "User", "Guest" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
        }

        await EnsureUserAsync(userManager, "admin", "admin@safevault.local", "Admin#123!", "Admin");
        await EnsureUserAsync(userManager, "user", "user@safevault.local", "User#123!", "User");
        await EnsureUserAsync(userManager, "guest", "guest@safevault.local", "Guest#123!", "Guest");
    }

    private static async Task EnsureUserAsync(
        UserManager<ApplicationUser> userManager,
        string username,
        string email,
        string password,
        string role)
    {
        var user = await userManager.FindByNameAsync(username);
        if (user is null)
        {
            user = new ApplicationUser
            {
                UserName = username,
                Email = email,
                EmailConfirmed = true
            };

            var createResult = await userManager.CreateAsync(user, password);
            if (!createResult.Succeeded)
            {
                return;
            }
        }

        if (!await userManager.IsInRoleAsync(user, role))
        {
            await userManager.AddToRoleAsync(user, role);
        }
    }
}
