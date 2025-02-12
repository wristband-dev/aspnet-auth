namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the configuration for login.
/// </summary>
public class LoginConfig
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LoginConfig"/> class.
    /// </summary>
    public LoginConfig()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginConfig"/> class with specified values.
    /// </summary>
    /// <param name="customState">Custom state data for the login request.</param>
    /// <param name="defaultTenantCustomDomain">An optional default tenant custom domain to use for the login request.</param>
    /// <param name="defaultTenantDomainName">An optional default tenant domain name to use for the login request.</param>
    public LoginConfig(Dictionary<string, object>? customState, string? defaultTenantCustomDomain, string? defaultTenantDomainName)
    {
        CustomState = customState;
        DefaultTenantCustomDomain = defaultTenantCustomDomain;
        DefaultTenantDomainName = defaultTenantDomainName;
    }

    /// <summary>
    /// Gets or sets custom state data for the login request.
    /// </summary>
    public Dictionary<string, object>? CustomState { get; set; }

    /// <summary>
    /// Gets or sets the optional default tenant custom domain to use for the login request.
    /// </summary>
    public string? DefaultTenantCustomDomain { get; set; }

    /// <summary>
    /// Gets or sets the optional default tenant domain name to use for the login request.
    /// </summary>
    public string? DefaultTenantDomainName { get; set; }
}
