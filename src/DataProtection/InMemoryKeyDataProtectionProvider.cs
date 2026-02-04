using Microsoft.AspNetCore.DataProtection;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Factory for creating IDataProtector instances with in-memory key derivation.
/// </summary>
internal class InMemoryKeyDataProtectionProvider : IDataProtectionProvider
{
    private readonly string[] _secrets;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryKeyDataProtectionProvider"/> class.
    /// </summary>
    /// <param name="secrets">
    /// Array of secrets to use for key derivation. The first secret is used for encryption,
    /// all secrets are used for decryption to support zero-downtime secret rotation.
    /// Each secret must be at least 32 characters long.
    /// </param>
    public InMemoryKeyDataProtectionProvider(string[] secrets)
    {
        _secrets = secrets;
    }

    /// <summary>
    /// Creates a data protector for a specific purpose.
    /// Purpose strings enable key isolation - different purposes derive different keys from the same secret.
    /// </summary>
    /// <param name="purpose">Purpose string for key isolation (e.g., "Authentication.Cookies", "CSRF").</param>
    /// <returns>An IDataProtector instance for the specified purpose.</returns>
    public IDataProtector CreateProtector(string purpose)
    {
        return new InMemoryKeyDataProtector(purpose, _secrets);
    }
}
