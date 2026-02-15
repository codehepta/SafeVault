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
    }
}
