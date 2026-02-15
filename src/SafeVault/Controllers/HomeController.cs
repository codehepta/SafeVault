using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Controllers;

/// <summary>
/// MVC controller for the SafeVault login page.
/// </summary>
public class HomeController : Controller
{
    private const string SessionUsernameKey = "SafeVault.Username";
    private const string SessionRoleKey = "SafeVault.Role";

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly AuthDbContext _dbContext;
    private readonly IDataProtector _vaultSecretProtector;
    private readonly ILogger<HomeController> _logger;

    /// <summary>
    /// Initializes a new instance of the home controller.
    /// </summary>
    /// <param name="userManager">Identity user manager.</param>
    /// <param name="signInManager">Identity sign-in manager.</param>
    /// <param name="logger">Application logger.</param>
    public HomeController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        AuthDbContext dbContext,
        IDataProtectionProvider dataProtectionProvider,
        ILogger<HomeController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _dbContext = dbContext;
        _vaultSecretProtector = dataProtectionProvider.CreateProtector("SafeVault.PasswordEntry.Secret.v1");
        _logger = logger;
    }

    /// <summary>
    /// Returns the login page.
    /// </summary>
    /// <returns>Login view model page.</returns>
    [HttpGet]
    public IActionResult Index()
    {
        if (IsSessionAuthenticated())
        {
            return RedirectToAction(nameof(Dashboard));
        }

        return View(new LoginPageViewModel());
    }

    /// <summary>
    /// Processes login form submissions.
    /// </summary>
    /// <param name="model">Login form data.</param>
    /// <returns>Login view with authentication result.</returns>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(LoginPageViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        string normalizedUsername;
        try
        {
            normalizedUsername = InputValidator.ValidateAndSanitizeUsername(model.Username);
        }
        catch (ArgumentException)
        {
            model.Message = "Invalid credentials.";
            return View(model);
        }

        var user = await _userManager.FindByNameAsync(normalizedUsername);

        if (user is null)
        {
            _logger.LogWarning("MVC login failed for unknown user {Username}", model.Username);
            model.Message = "Invalid credentials.";
            return View(model);
        }

        var passwordResult = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
        if (!passwordResult.Succeeded)
        {
            _logger.LogWarning("MVC login failed for user {Username}", model.Username);
            model.Message = "Invalid credentials.";
            return View(model);
        }

        var roles = await _userManager.GetRolesAsync(user);
        var role = roles.FirstOrDefault() ?? "Guest";

        model.Message = string.Equals(role, "Admin", StringComparison.OrdinalIgnoreCase)
            ? $"Welcome {user.UserName}. You can access admin features."
            : $"Welcome {user.UserName}. You are logged in as a {role.ToLowerInvariant()} user.";

        HttpContext.Session.SetString(SessionUsernameKey, user.UserName ?? normalizedUsername);
        HttpContext.Session.SetString(SessionRoleKey, role);
        TempData["DashboardMessage"] = model.Message;

        _logger.LogInformation("MVC login succeeded for user {Username}; redirecting to dashboard", normalizedUsername);
        return RedirectToAction(nameof(Dashboard));
    }

    /// <summary>
    /// Returns the registration page.
    /// </summary>
    /// <returns>Registration view model page.</returns>
    [HttpGet]
    public IActionResult Register()
    {
        return View(new RegisterPageViewModel());
    }

    /// <summary>
    /// Processes registration form submissions.
    /// </summary>
    /// <param name="model">Registration form data.</param>
    /// <returns>Registration view with creation result.</returns>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterPageViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        string normalizedUsername;
        string normalizedEmail;
        try
        {
            normalizedUsername = InputValidator.ValidateAndSanitizeUsername(model.Username);
            normalizedEmail = InputValidator.ValidateAndNormalizeEmail(model.Email);
        }
        catch (ArgumentException)
        {
            model.Message = "Invalid registration input.";
            return View(model);
        }

        var user = new ApplicationUser
        {
            UserName = normalizedUsername,
            Email = normalizedEmail,
            EmailConfirmed = true
        };

        var createResult = await _userManager.CreateAsync(user, model.Password);
        if (!createResult.Succeeded)
        {
            model.Message = "Registration failed.";
            foreach (var error in createResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            _logger.LogWarning("MVC registration failed for user {Username}", normalizedUsername);
            return View(model);
        }

        await _userManager.AddToRoleAsync(user, "User");
        _logger.LogInformation("MVC user {Username} registered successfully", normalizedUsername);

        model.Message = "Registration successful. You can now sign in from the login page.";
        model.Password = string.Empty;
        return View(model);
    }

    /// <summary>
    /// Returns the API demo page.
    /// </summary>
    /// <returns>API demo view.</returns>
    [HttpGet]
    public IActionResult ApiDemo()
    {
        return View();
    }

    /// <summary>
    /// Returns the signed-in user dashboard.
    /// </summary>
    /// <returns>Dashboard view or unauthorized page redirect.</returns>
    [HttpGet]
    public async Task<IActionResult> Dashboard()
    {
        if (!TryGetSessionIdentity(out var username, out _))
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
        {
            ClearSession();
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        var roles = await _userManager.GetRolesAsync(user);
        var role = roles.FirstOrDefault() ?? "Guest";
        HttpContext.Session.SetString(SessionRoleKey, role);

        var storedEntries = await _dbContext.PasswordEntries
            .Where(entry => entry.UserId == user.Id)
            .OrderByDescending(entry => entry.CreatedAtUtc)
            .Select(entry => new PasswordEntryViewModel
            {
                Id = entry.Id,
                Label = entry.Label,
                LoginName = entry.LoginName,
                MaskedSecret = entry.Secret,
                CreatedAtUtc = entry.CreatedAtUtc
            })
            .ToListAsync();

        var entries = storedEntries
            .Select(entry =>
            {
                var plaintextSecret = ReadSecret(entry.MaskedSecret);
                return new PasswordEntryViewModel
                {
                    Id = entry.Id,
                    Label = entry.Label,
                    LoginName = entry.LoginName,
                    MaskedSecret = MaskSecret(plaintextSecret),
                    CreatedAtUtc = entry.CreatedAtUtc
                };
            })
            .ToList();

        var model = new DashboardViewModel
        {
            Username = username,
            Role = role,
            Message = TempData["DashboardMessage"] as string,
            PasswordEntries = entries
        };

        return View(model);
    }

    /// <summary>
    /// Returns admin-only panel for user vault management.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> AdminPanel()
    {
        if (!TryGetSessionIdentity(out _, out _) || !await IsAdminSessionAsync())
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        var users = await _userManager.Users
            .OrderBy(user => user.UserName)
            .ToListAsync();

        var vaultCounts = await _dbContext.PasswordEntries
            .GroupBy(entry => entry.UserId)
            .Select(group => new { UserId = group.Key, Count = group.Count() })
            .ToDictionaryAsync(item => item.UserId, item => item.Count);

        var rows = new List<AdminUserVaultViewModel>(users.Count);
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            rows.Add(new AdminUserVaultViewModel
            {
                UserId = user.Id,
                Username = user.UserName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                Roles = roles.Count == 0 ? "-" : string.Join(", ", roles),
                VaultCount = vaultCounts.GetValueOrDefault(user.Id)
            });
        }

        var model = new AdminPanelViewModel
        {
            Message = TempData["AdminMessage"] as string,
            Users = rows
        };

        return View(model);
    }

    /// <summary>
    /// Clears all vault entries for a selected user (admin only).
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AdminClearUserVault(string userId)
    {
        if (!TryGetSessionIdentity(out _, out _) || !await IsAdminSessionAsync())
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        if (string.IsNullOrWhiteSpace(userId))
        {
            TempData["AdminMessage"] = "Invalid user target.";
            return RedirectToAction(nameof(AdminPanel));
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            TempData["AdminMessage"] = "User not found.";
            return RedirectToAction(nameof(AdminPanel));
        }

        var entries = await _dbContext.PasswordEntries
            .Where(entry => entry.UserId == userId)
            .ToListAsync();

        _dbContext.PasswordEntries.RemoveRange(entries);
        await _dbContext.SaveChangesAsync();

        TempData["AdminMessage"] = $"Cleared {entries.Count} vault entries for user {user.UserName}.";
        _logger.LogInformation("Admin cleared {Count} vault entries for user {Username}", entries.Count, user.UserName);

        return RedirectToAction(nameof(AdminPanel));
    }

    /// <summary>
    /// Returns admin-only page to edit a user profile and primary role.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> AdminEditUser(string userId)
    {
        if (!TryGetSessionIdentity(out _, out _) || !await IsAdminSessionAsync())
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        if (string.IsNullOrWhiteSpace(userId))
        {
            return RedirectToAction(nameof(AdminPanel));
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            TempData["AdminMessage"] = "User not found.";
            return RedirectToAction(nameof(AdminPanel));
        }

        var currentRoles = await _userManager.GetRolesAsync(user);
        var model = new AdminEditUserViewModel
        {
            UserId = user.Id,
            Username = user.UserName ?? string.Empty,
            Email = user.Email ?? string.Empty,
            Role = currentRoles.FirstOrDefault() ?? "User"
        };

        return View(model);
    }

    /// <summary>
    /// Updates user profile fields and role (admin only).
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AdminEditUser(AdminEditUserViewModel model)
    {
        if (!TryGetSessionIdentity(out var adminUsername, out _) || !await IsAdminSessionAsync())
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user is null)
        {
            TempData["AdminMessage"] = "User not found.";
            return RedirectToAction(nameof(AdminPanel));
        }

        string normalizedUsername;
        string normalizedEmail;
        try
        {
            normalizedUsername = InputValidator.ValidateAndSanitizeUsername(model.Username);
            normalizedEmail = InputValidator.ValidateAndNormalizeEmail(model.Email);
        }
        catch (ArgumentException)
        {
            ModelState.AddModelError(string.Empty, "Invalid username or email.");
            return View(model);
        }

        var normalizedRole = model.Role.Trim();
        if (!string.Equals(normalizedRole, "Admin", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(normalizedRole, "User", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(normalizedRole, "Guest", StringComparison.OrdinalIgnoreCase))
        {
            ModelState.AddModelError(string.Empty, "Invalid role selection.");
            return View(model);
        }

        user.UserName = normalizedUsername;
        user.Email = normalizedEmail;

        var updateUserResult = await _userManager.UpdateAsync(user);
        if (!updateUserResult.Succeeded)
        {
            foreach (var error in updateUserResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        var desiredRole = char.ToUpperInvariant(normalizedRole[0]) + normalizedRole[1..].ToLowerInvariant();
        var existingRoles = await _userManager.GetRolesAsync(user);
        var removeRolesResult = await _userManager.RemoveFromRolesAsync(user, existingRoles);
        if (!removeRolesResult.Succeeded)
        {
            foreach (var error in removeRolesResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        var addRoleResult = await _userManager.AddToRoleAsync(user, desiredRole);
        if (!addRoleResult.Succeeded)
        {
            foreach (var error in addRoleResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        if (string.Equals(adminUsername, HttpContext.Session.GetString(SessionUsernameKey), StringComparison.OrdinalIgnoreCase)
            && string.Equals(adminUsername, normalizedUsername, StringComparison.OrdinalIgnoreCase))
        {
            HttpContext.Session.SetString(SessionRoleKey, desiredRole);
        }

        TempData["AdminMessage"] = $"Updated user {normalizedUsername}.";
        return RedirectToAction(nameof(AdminPanel));
    }

    /// <summary>
    /// Deletes a user and related vault/token data (admin only).
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AdminDeleteUser(string userId)
    {
        if (!TryGetSessionIdentity(out var adminUsername, out _) || !await IsAdminSessionAsync())
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        if (string.IsNullOrWhiteSpace(userId))
        {
            TempData["AdminMessage"] = "Invalid user target.";
            return RedirectToAction(nameof(AdminPanel));
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            TempData["AdminMessage"] = "User not found.";
            return RedirectToAction(nameof(AdminPanel));
        }

        if (string.Equals(user.UserName, adminUsername, StringComparison.OrdinalIgnoreCase))
        {
            TempData["AdminMessage"] = "You cannot delete your own admin account.";
            return RedirectToAction(nameof(AdminPanel));
        }

        var entries = await _dbContext.PasswordEntries
            .Where(entry => entry.UserId == userId)
            .ToListAsync();
        _dbContext.PasswordEntries.RemoveRange(entries);

        var refreshTokens = await _dbContext.RefreshTokens
            .Where(token => token.UserId == userId)
            .ToListAsync();
        _dbContext.RefreshTokens.RemoveRange(refreshTokens);

        await _dbContext.SaveChangesAsync();

        var deleteResult = await _userManager.DeleteAsync(user);
        if (!deleteResult.Succeeded)
        {
            TempData["AdminMessage"] = "Failed to delete user.";
            return RedirectToAction(nameof(AdminPanel));
        }

        TempData["AdminMessage"] = $"Deleted user {user.UserName}.";
        return RedirectToAction(nameof(AdminPanel));
    }

    /// <summary>
    /// Adds a password entry to the current user's vault.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddPassword(string label, string loginName, string secret)
    {
        if (!TryGetSessionIdentity(out var username, out _))
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        if (string.IsNullOrWhiteSpace(label) || string.IsNullOrWhiteSpace(loginName) || string.IsNullOrWhiteSpace(secret))
        {
            TempData["DashboardMessage"] = "All password entry fields are required.";
            return RedirectToAction(nameof(Dashboard));
        }

        if (InputValidator.ContainsPotentialXss(label) || InputValidator.ContainsPotentialXss(loginName) || label.Length > 100 || loginName.Length > 100 || secret.Length > 256)
        {
            TempData["DashboardMessage"] = "Invalid password entry values.";
            return RedirectToAction(nameof(Dashboard));
        }

        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
        {
            ClearSession();
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        _dbContext.PasswordEntries.Add(new PasswordEntry
        {
            UserId = user.Id,
            Label = label.Trim(),
            LoginName = loginName.Trim(),
            Secret = _vaultSecretProtector.Protect(secret),
            CreatedAtUtc = DateTime.UtcNow
        });

        await _dbContext.SaveChangesAsync();
        TempData["DashboardMessage"] = "Password entry added.";
        return RedirectToAction(nameof(Dashboard));
    }

    /// <summary>
    /// Removes a password entry from the current user's vault.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemovePassword(int id)
    {
        if (!TryGetSessionIdentity(out var username, out _))
        {
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
        {
            ClearSession();
            return RedirectToAction(nameof(UnauthorizedPage));
        }

        var entry = await _dbContext.PasswordEntries
            .FirstOrDefaultAsync(passwordEntry => passwordEntry.Id == id && passwordEntry.UserId == user.Id);

        if (entry is null)
        {
            TempData["DashboardMessage"] = "Password entry not found.";
            return RedirectToAction(nameof(Dashboard));
        }

        _dbContext.PasswordEntries.Remove(entry);
        await _dbContext.SaveChangesAsync();
        TempData["DashboardMessage"] = "Password entry removed.";
        return RedirectToAction(nameof(Dashboard));
    }

    /// <summary>
    /// Returns plaintext secret for a specific vault entry after authorization checks.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> GetPasswordSecret(int id)
    {
        if (!TryGetSessionIdentity(out var username, out _))
        {
            return Unauthorized();
        }

        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
        {
            ClearSession();
            return Unauthorized();
        }

        var entry = await _dbContext.PasswordEntries
            .FirstOrDefaultAsync(passwordEntry => passwordEntry.Id == id && passwordEntry.UserId == user.Id);

        if (entry is null)
        {
            return NotFound();
        }

        try
        {
            var secret = _vaultSecretProtector.Unprotect(entry.Secret);
            return Json(new { Secret = secret });
        }
        catch
        {
            if (string.IsNullOrWhiteSpace(entry.Secret))
            {
                return BadRequest(new { Message = "Unable to read password entry." });
            }

            return Json(new { Secret = entry.Secret });
        }
    }

    /// <summary>
    /// Logs the current MVC user out.
    /// </summary>
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Logout()
    {
        ClearSession();
        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Returns unauthorized access page.
    /// </summary>
    [HttpGet]
    public IActionResult UnauthorizedPage()
    {
        return View("Unauthorized");
    }

    private bool IsSessionAuthenticated()
    {
        return TryGetSessionIdentity(out _, out _);
    }

    private async Task<bool> IsAdminSessionAsync()
    {
        if (!TryGetSessionIdentity(out var username, out _))
        {
            return false;
        }

        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
        {
            return false;
        }

        var isAdmin = await _userManager.IsInRoleAsync(user, "Admin");
        HttpContext.Session.SetString(SessionRoleKey, isAdmin ? "Admin" : "User");
        return isAdmin;
    }

    private string ReadSecret(string storedValue)
    {
        if (string.IsNullOrWhiteSpace(storedValue))
        {
            return string.Empty;
        }

        try
        {
            return _vaultSecretProtector.Unprotect(storedValue);
        }
        catch
        {
            return storedValue;
        }
    }

    private bool TryGetSessionIdentity(out string username, out string role)
    {
        username = HttpContext.Session.GetString(SessionUsernameKey) ?? string.Empty;
        role = HttpContext.Session.GetString(SessionRoleKey) ?? string.Empty;
        return !string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(role);
    }

    private void ClearSession()
    {
        HttpContext.Session.Remove(SessionUsernameKey);
        HttpContext.Session.Remove(SessionRoleKey);
    }

    private static string MaskSecret(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return string.Empty;
        }

        if (secret.Length <= 3)
        {
            return new string('*', secret.Length);
        }

        return $"{new string('*', secret.Length - 2)}{secret[^2..]}";
    }
}
