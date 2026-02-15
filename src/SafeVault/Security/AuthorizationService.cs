using SafeVault.Models;

namespace SafeVault.Security;

/// <summary>
/// Provides role-based authorization checks for SafeVault features.
/// </summary>
public static class AuthorizationService
{
    /// <summary>
    /// Determines whether an authenticated user can access admin dashboard functionality.
    /// </summary>
    /// <param name="user">Authenticated user identity.</param>
    /// <returns><c>true</c> when the user has the admin role; otherwise <c>false</c>.</returns>
    public static bool CanAccessAdminDashboard(AuthenticatedUser? user)
    {
        return user is not null && user.Role == UserRole.Admin;
    }

    /// <summary>
    /// Determines whether an authenticated user has a required role.
    /// </summary>
    /// <param name="user">Authenticated user identity.</param>
    /// <param name="requiredRole">Role required for access.</param>
    /// <returns><c>true</c> when the user has the required role; otherwise <c>false</c>.</returns>
    public static bool HasRequiredRole(AuthenticatedUser? user, UserRole requiredRole)
    {
        return user is not null && user.Role == requiredRole;
    }
}