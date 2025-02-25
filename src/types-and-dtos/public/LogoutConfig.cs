namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the configuration for logout.
/// </summary>
public class LogoutConfig
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutConfig"/> class.
    /// </summary>
    public LogoutConfig()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LogoutConfig"/> class with specified values.
    /// </summary>
    /// <param name="redirectUrl">Optional URL that the logout endpoint will redirect to after completing the logout operation.</param>
    /// <param name="refreshToken">The refresh token to revoke during logout.</param>
    /// <param name="tenantCustomDomain">The tenant custom domain for the tenant the user belongs to.</param>
    /// <param name="tenantDomainName">The domain name of the tenant the user belongs to.</param>
    public LogoutConfig(string? redirectUrl, string? refreshToken, string? tenantCustomDomain, string? tenantDomainName)
    {
        RedirectUrl = redirectUrl;
        RefreshToken = refreshToken;
        TenantCustomDomain = tenantCustomDomain;
        TenantDomainName = tenantDomainName;
    }

    /// <summary>
    /// Gets or sets the optional URL that the logout endpoint will redirect to after completing the logout operation.
    /// </summary>
    public string? RedirectUrl { get; set; }

    /// <summary>
    /// Gets or sets the refresh token to revoke during logout.
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Gets or sets the tenant custom domain for the tenant that the user belongs to (if applicable).
    /// </summary>
    public string? TenantCustomDomain { get; set; }

    /// <summary>
    /// Gets or sets the domain name of the tenant the user belongs to.
    /// </summary>
    public string? TenantDomainName { get; set; }
}
