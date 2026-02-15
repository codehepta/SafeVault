using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestLoginSecurity
{
    [Test]
    public void LoginUser_WithValidCredentials_ReturnsTrue()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var result = service.LoginUser("alice", "P@ssw0rd!");

        Assert.That(result, Is.True);
    }

    [Test]
    public void LoginUser_WithInvalidPassword_ReturnsFalse()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var result = service.LoginUser("alice", "WrongPass1!");

        Assert.That(result, Is.False);
    }

    [Test]
    public void LoginUser_WithSqlInjectionPayload_ReturnsFalse()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var result = service.LoginUser("alice", "' OR 1=1 --");

        Assert.That(result, Is.False);
    }

    [Test]
    public void AuthenticateUser_WithInvalidUsernameCharacters_ReturnsNull()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var result = service.AuthenticateUser("alice';--", "P@ssw0rd!");

        Assert.That(result, Is.Null);
    }

    [Test]
    public void AdminUser_CanAccessAdminDashboard()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var user = service.AuthenticateUser("alice", "P@ssw0rd!");
        var canAccess = AuthorizationService.CanAccessAdminDashboard(user);

        Assert.That(user, Is.Not.Null);
        Assert.That(canAccess, Is.True);
    }

    [Test]
    public void StandardUser_CannotAccessAdminDashboard()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var user = service.AuthenticateUser("bob", "S3cur3#Pass");
        var canAccess = AuthorizationService.CanAccessAdminDashboard(user);

        Assert.That(user, Is.Not.Null);
        Assert.That(canAccess, Is.False);
    }

    [Test]
    public void RegisterUser_WithValidInput_CreatesUserAndAllowsLogin()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var registered = service.RegisterUser("charlie", "S3cure#12", "charlie@example.com");
        var authenticated = service.AuthenticateUser("charlie", "S3cure#12");

        Assert.That(registered, Is.True);
        Assert.That(authenticated, Is.Not.Null);
        Assert.That(authenticated!.Role, Is.EqualTo(SafeVault.Models.UserRole.User));
    }

    [Test]
    public void RegisterUser_WithDuplicateUsername_ReturnsFalse()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var registered = service.RegisterUser("alice", "Another#12", "alice2@example.com");

        Assert.That(registered, Is.False);
    }

    [Test]
    public void RegisterUser_StoresHashedPassword_NotPlaintext()
    {
        using var connection = BuildInMemoryDatabase();
        var service = new LoginService(connection);

        var registered = service.RegisterUser("diana", "Strong#123", "diana@example.com");

        Assert.That(registered, Is.True);

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT PasswordHash, PasswordSalt FROM Users WHERE Username = @username;";
        command.Parameters.AddWithValue("@username", "diana");

        using var reader = command.ExecuteReader();
        Assert.That(reader.Read(), Is.True);

        var storedHash = reader.GetString(0);
        var storedSalt = reader.GetString(1);

        Assert.That(storedHash, Is.Not.EqualTo("Strong#123"));
        Assert.That(storedSalt, Is.Not.Empty);
    }

    private static SqliteConnection BuildInMemoryDatabase()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        var (aliceHash, aliceSalt) = PasswordHasher.HashPassword("P@ssw0rd!");
        var (bobHash, bobSalt) = PasswordHasher.HashPassword("S3cur3#Pass");

        using var createCommand = connection.CreateCommand();
        createCommand.CommandText = @"
            CREATE TABLE Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                PasswordHash TEXT NOT NULL,
                PasswordSalt TEXT NOT NULL,
                Email TEXT NOT NULL,
                Role TEXT NOT NULL
            );
            INSERT INTO Users (Username, PasswordHash, PasswordSalt, Email, Role) VALUES (@aliceUsername, @aliceHash, @aliceSalt, @aliceEmail, @aliceRole);
            INSERT INTO Users (Username, PasswordHash, PasswordSalt, Email, Role) VALUES (@bobUsername, @bobHash, @bobSalt, @bobEmail, @bobRole);";

        createCommand.Parameters.AddWithValue("@aliceUsername", "alice");
        createCommand.Parameters.AddWithValue("@aliceHash", aliceHash);
        createCommand.Parameters.AddWithValue("@aliceSalt", aliceSalt);
        createCommand.Parameters.AddWithValue("@aliceEmail", "alice@example.com");
        createCommand.Parameters.AddWithValue("@aliceRole", "admin");

        createCommand.Parameters.AddWithValue("@bobUsername", "bob");
        createCommand.Parameters.AddWithValue("@bobHash", bobHash);
        createCommand.Parameters.AddWithValue("@bobSalt", bobSalt);
        createCommand.Parameters.AddWithValue("@bobEmail", "bob@example.com");
        createCommand.Parameters.AddWithValue("@bobRole", "user");

        createCommand.ExecuteNonQuery();

        return connection;
    }
}