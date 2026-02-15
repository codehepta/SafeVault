using System.Data;
using SafeVault.Helpers;
using SafeVault.Models;

namespace SafeVault.Security;

/// <summary>
/// Performs user authentication with validated input and parameterized data access.
/// </summary>
public class LoginService
{
    private readonly IDbConnection _connection;

    /// <summary>
    /// Initializes a new login service.
    /// </summary>
    /// <param name="connection">Database connection used for credential lookup.</param>
    public LoginService(IDbConnection connection)
    {
        _connection = connection;
    }

    /// <summary>
    /// Authenticates a user by username and password.
    /// </summary>
    /// <param name="username">Username supplied by the caller.</param>
    /// <param name="password">Plaintext password supplied by the caller.</param>
    /// <returns><c>true</c> when credentials are valid; otherwise <c>false</c>.</returns>
    public bool LoginUser(string username, string password)
    {
        return AuthenticateUser(username, password) is not null;
    }

    /// <summary>
    /// Authenticates a user and returns role-aware identity information when successful.
    /// </summary>
    /// <param name="username">Username supplied by the caller.</param>
    /// <param name="password">Plaintext password supplied by the caller.</param>
    /// <returns>The authenticated user; otherwise <c>null</c>.</returns>
    public AuthenticatedUser? AuthenticateUser(string username, string password)
    {
        const string allowedSpecialCharacters = "!@#$%^&*?";

        string normalizedUsername;
        try
        {
            normalizedUsername = InputValidator.ValidateAndSanitizeUsername(username);
        }
        catch (ArgumentException)
        {
            return null;
        }

        if (!ValidationHelpers.IsValidInput(password, allowedSpecialCharacters))
        {
            return null;
        }

        const string query = "SELECT Username, PasswordHash, PasswordSalt, Role FROM Users WHERE Username = @Username;";

        var shouldCloseConnection = _connection.State != ConnectionState.Open;
        if (shouldCloseConnection)
        {
            _connection.Open();
        }

        try
        {
            using var command = _connection.CreateCommand();
            command.CommandText = query;

            AddParameter(command, "@Username", normalizedUsername);
            using var reader = command.ExecuteReader();
            if (!reader.Read())
            {
                return null;
            }

            var storedHash = reader.GetString(1);
            var storedSalt = reader.GetString(2);
            if (!PasswordHasher.VerifyPassword(password, storedHash, storedSalt))
            {
                return null;
            }

            var roleValue = reader.IsDBNull(3) ? string.Empty : reader.GetString(3);
            var role = ParseRole(roleValue);

            return new AuthenticatedUser
            {
                Username = reader.GetString(0),
                Role = role
            };
        }
        finally
        {
            if (shouldCloseConnection)
            {
                _connection.Close();
            }
        }
    }

    /// <summary>
    /// Registers a new user with a securely hashed password.
    /// </summary>
    /// <param name="username">New user's username.</param>
    /// <param name="password">New user's plaintext password.</param>
    /// <param name="email">New user's email address.</param>
    /// <param name="role">Role assigned to the new user.</param>
    /// <returns><c>true</c> when registration succeeds; otherwise <c>false</c>.</returns>
    public bool RegisterUser(string username, string password, string email, UserRole role = UserRole.User)
    {
        const string allowedSpecialCharacters = "!@#$%^&*?";

        string normalizedUsername;
        string normalizedEmail;
        try
        {
            normalizedUsername = InputValidator.ValidateAndSanitizeUsername(username);
            normalizedEmail = InputValidator.ValidateAndNormalizeEmail(email);
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (!ValidationHelpers.IsValidInput(password, allowedSpecialCharacters)
            || password.Length < 8)
        {
            return false;
        }

        var shouldCloseConnection = _connection.State != ConnectionState.Open;
        if (shouldCloseConnection)
        {
            _connection.Open();
        }

        try
        {
            using var existsCommand = _connection.CreateCommand();
            existsCommand.CommandText = "SELECT 1 FROM Users WHERE Username = @Username LIMIT 1;";
            AddParameter(existsCommand, "@Username", normalizedUsername);

            var exists = existsCommand.ExecuteScalar();
            if (exists is not null)
            {
                return false;
            }

            var (passwordHash, passwordSalt) = PasswordHasher.HashPassword(password);

            using var insertCommand = _connection.CreateCommand();
            insertCommand.CommandText = @"INSERT INTO Users (Username, PasswordHash, PasswordSalt, Email, Role)
                                          VALUES (@Username, @PasswordHash, @PasswordSalt, @Email, @Role);";

            AddParameter(insertCommand, "@Username", normalizedUsername);
            AddParameter(insertCommand, "@PasswordHash", passwordHash);
            AddParameter(insertCommand, "@PasswordSalt", passwordSalt);
            AddParameter(insertCommand, "@Email", normalizedEmail);
            AddParameter(insertCommand, "@Role", role.ToString().ToLowerInvariant());

            return insertCommand.ExecuteNonQuery() == 1;
        }
        finally
        {
            if (shouldCloseConnection)
            {
                _connection.Close();
            }
        }
    }

    /// <summary>
    /// Adds a strongly-typed database parameter to a command.
    /// </summary>
    private static void AddParameter(IDbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }

    private static UserRole ParseRole(string role)
    {
        if (Enum.TryParse<UserRole>(role, ignoreCase: true, out var parsedRole))
        {
            return parsedRole;
        }

        return UserRole.User;
    }
}