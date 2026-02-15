using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Controllers;

/// <summary>
/// MVC controller for the SafeVault login page.
/// </summary>
public class HomeController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
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
        ILogger<HomeController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _logger = logger;
    }

    /// <summary>
    /// Returns the login page.
    /// </summary>
    /// <returns>Login view model page.</returns>
    [HttpGet]
    public IActionResult Index()
    {
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

        model.Role = role;
        return View(model);
    }
}
