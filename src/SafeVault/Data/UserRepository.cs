using System.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Data;

/// <summary>
/// Handles user data access using parameterized SQL queries.
/// </summary>
public class UserRepository
{
    private readonly IDbConnection _connection;

    /// <summary>
    /// Initializes a new repository with a database connection.
    /// </summary>
    /// <param name="connection">Open or reusable database connection.</param>
    public UserRepository(IDbConnection connection)
    {
        _connection = connection;
    }

    /// <summary>
    /// Fetches a user by username using a parameterized query.
    /// </summary>
    /// <param name="username">Username to search for.</param>
    /// <returns>The matching user, or <c>null</c> if not found.</returns>
    public User? GetUserByUsername(string username)
    {
        string normalizedUsername;
        try
        {
            normalizedUsername = InputValidator.ValidateAndSanitizeUsername(username);
        }
        catch (ArgumentException)
        {
            return null;
        }

        const string sql = "SELECT UserID, Username, Email FROM Users WHERE Username = @username;";

        using var command = _connection.CreateCommand();
        command.CommandText = sql;

        var parameter = command.CreateParameter();
        parameter.ParameterName = "@username";
        parameter.Value = normalizedUsername;
        command.Parameters.Add(parameter);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new User
        {
            UserId = reader.GetInt32(0),
            Username = reader.GetString(1),
            Email = reader.GetString(2)
        };
    }
}