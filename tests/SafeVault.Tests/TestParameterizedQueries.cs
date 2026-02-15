using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Data;

namespace SafeVault.Tests;

[TestFixture]
public class TestParameterizedQueries
{
    [Test]
    public void SQLInjectionPayload_DoesNotBypassLookup()
    {
        using var connection = BuildInMemoryDatabase();
        var repository = new UserRepository(connection);

        var result = repository.GetUserByUsername("' OR 1=1 --");

        Assert.That(result, Is.Null);
    }

    [Test]
    public void ValidUsername_ReturnsExpectedUser()
    {
        using var connection = BuildInMemoryDatabase();
        var repository = new UserRepository(connection);

        var result = repository.GetUserByUsername("alice");

        Assert.That(result, Is.Not.Null);
        Assert.That(result!.Email, Is.EqualTo("alice@example.com"));
    }

    private static SqliteConnection BuildInMemoryDatabase()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        using var createCommand = connection.CreateCommand();
        createCommand.CommandText = @"
            CREATE TABLE Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Email TEXT NOT NULL
            );
            INSERT INTO Users (Username, Email) VALUES ('alice', 'alice@example.com');
            INSERT INTO Users (Username, Email) VALUES ('bob', 'bob@example.com');";
        createCommand.ExecuteNonQuery();

        return connection;
    }
}