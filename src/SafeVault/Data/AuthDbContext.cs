using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data;

/// <summary>
/// Entity Framework database context for ASP.NET Identity and refresh tokens.
/// </summary>
public class AuthDbContext : IdentityDbContext<ApplicationUser>
{
    /// <summary>
    /// Initializes a new auth database context.
    /// </summary>
    public AuthDbContext(DbContextOptions<AuthDbContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Gets or sets stored refresh tokens.
    /// </summary>
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    /// <summary>
    /// Gets or sets per-user password vault entries.
    /// </summary>
    public DbSet<PasswordEntry> PasswordEntries => Set<PasswordEntry>();

    /// <summary>
    /// Configures model metadata for auth entities.
    /// </summary>
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(token => token.Id);
            entity.Property(token => token.TokenHash).HasMaxLength(128).IsRequired();
            entity.Property(token => token.UserId).IsRequired();
            entity.HasIndex(token => token.TokenHash).IsUnique();
        });

        builder.Entity<PasswordEntry>(entity =>
        {
            entity.HasKey(entry => entry.Id);
            entity.Property(entry => entry.UserId).IsRequired();
            entity.Property(entry => entry.Label).HasMaxLength(100).IsRequired();
            entity.Property(entry => entry.LoginName).HasMaxLength(100).IsRequired();
            entity.Property(entry => entry.Secret).HasMaxLength(256).IsRequired();
            entity.HasIndex(entry => entry.UserId);
        });
    }
}
