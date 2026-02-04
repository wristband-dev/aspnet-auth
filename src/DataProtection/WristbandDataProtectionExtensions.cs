using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Provides in-memory key-based data protection using HKDF key derivation and AES-GCM encryption.
/// This implementation derives encryption keys from provided secrets, eliminating the need for
/// persistent storage or external key management infrastructure.
/// </summary>
public static class WristbandDataProtectionExtensions
{
    /// <summary>
    /// Configures data protection to use a single in-memory encryption key derived from a secret.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="secret">The secret string (minimum 32 characters required).</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddInMemoryKeyDataProtection(this IServiceCollection services, string secret)
    {
        return services.AddInMemoryKeyDataProtection([secret]);
    }

    /// <summary>
    /// Configures data protection to use multiple in-memory encryption keys for rotation support.
    /// The first secret is used for encryption, all secrets are tried for decryption.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="secrets">Array of secret strings (max 3, minimum 32 characters each required).</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddInMemoryKeyDataProtection(this IServiceCollection services, string[] secrets)
    {
        if (secrets == null || secrets.Length == 0)
        {
            throw new ArgumentException("At least one secret must be provided.", nameof(secrets));
        }

        if (secrets.Length > 3)
        {
            throw new ArgumentException("Maximum 3 secrets are supported for rotation.", nameof(secrets));
        }

        foreach (var secret in secrets)
        {
            if (string.IsNullOrWhiteSpace(secret))
            {
                throw new ArgumentException("Secrets cannot be null or whitespace.", nameof(secrets));
            }

            if (secret.Length < 32)
            {
                throw new ArgumentException(
                    $"Secret must be at least 32 characters long. Provided secret length: {secret.Length}",
                    nameof(secrets));
            }
        }

        // Best practice: Use TryAdd to prevent accidental duplicate registrations.
        // First registration wins - if user registered a custom IDataProtectionProvider first,
        // theirs will be used. Otherwise, ours is registered.
        services.TryAddSingleton<IDataProtectionProvider>(sp => new InMemoryKeyDataProtectionProvider(secrets));

        return services;
    }
}
