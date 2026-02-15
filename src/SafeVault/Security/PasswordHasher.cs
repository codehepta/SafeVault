using System.Security.Cryptography;

namespace SafeVault.Security;

/// <summary>
/// Provides password hashing and verification using PBKDF2 with SHA-256.
/// </summary>
public static class PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 100_000;

    /// <summary>
    /// Creates a salted PBKDF2 hash for a plaintext password.
    /// </summary>
    /// <param name="password">Plaintext password.</param>
    /// <returns>Tuple containing base64 hash and base64 salt.</returns>
    public static (string PasswordHash, string PasswordSalt) HashPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password is required.", nameof(password));
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);

        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    /// <summary>
    /// Verifies a plaintext password against stored hash and salt values.
    /// </summary>
    /// <param name="password">Plaintext password to verify.</param>
    /// <param name="storedHash">Stored base64 PBKDF2 hash.</param>
    /// <param name="storedSalt">Stored base64 salt.</param>
    /// <returns><c>true</c> when the password matches; otherwise <c>false</c>.</returns>
    public static bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        if (string.IsNullOrWhiteSpace(password)
            || string.IsNullOrWhiteSpace(storedHash)
            || string.IsNullOrWhiteSpace(storedSalt))
        {
            return false;
        }

        byte[] hash;
        byte[] salt;
        try
        {
            hash = Convert.FromBase64String(storedHash);
            salt = Convert.FromBase64String(storedSalt);
        }
        catch (FormatException)
        {
            return false;
        }

        var computedHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, hash.Length);
        return CryptographicOperations.FixedTimeEquals(hash, computedHash);
    }
}