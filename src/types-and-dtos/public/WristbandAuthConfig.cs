namespace Wristband.AspNet.Auth;

/// <summary>
/// This is the primary SDK configuration for integrating Wristband authentication.
/// </summary>
public class WristbandAuthConfig
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthConfig"/> class.
    /// </summary>
    public WristbandAuthConfig()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthConfig"/> class with the specified configuration values.
    /// </summary>
    /// <param name="autoConfigureEnabled">Flag that tells the SDK to automatically set some of the SDK configuration values by calling to Wristband's SDK Auto-Configuration Endpoint.</param>
    /// <param name="clientId">The client ID for the application.</param>
    /// <param name="clientSecret">The client secret for the application.</param>
    /// <param name="customApplicationLoginPageUrl">Custom application login (tenant discovery) page URL if self-hosting the application login/tenant discovery UI.</param>
    /// <param name="dangerouslyDisableSecureCookies">If set to true, the "Secure" attribute will not be included in any cookie settings. Should be used only in local development.</param>
    /// <param name="isApplicationCustomDomainActive">Indicates whether an application-level custom domain is active for the Wristband application.</param>
    /// <param name="loginStateSecret">A secret (32 or more characters in length) used for encryption and decryption of login state cookies.</param>
    /// <param name="loginUrl">The URL for initiating the login request.</param>
    /// <param name="redirectUri">The redirect URI for callback after authentication.</param>
    /// <param name="parseTenantFromRootDomain">The root domain for your application.</param>
    /// <param name="scopes">The scopes required for authentication.</param>
    /// <param name="tokenExpirationBuffer">Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls.</param>
    /// <param name="wristbandApplicationVanityDomain">The vanity domain of the Wristband application.</param>
    public WristbandAuthConfig(
        string? clientId,
        string? clientSecret,
        string? loginStateSecret,
        string? loginUrl,
        string? redirectUri,
        string? wristbandApplicationVanityDomain,
        string? customApplicationLoginPageUrl,
        bool? dangerouslyDisableSecureCookies,
        string? parseTenantFromRootDomain,
        List<string>? scopes,
        bool? isApplicationCustomDomainActive,
        int? tokenExpirationBuffer,
        bool? autoConfigureEnabled = null)
    {
        ClientId = clientId;
        ClientSecret = clientSecret;
        LoginStateSecret = loginStateSecret;
        LoginUrl = loginUrl;
        RedirectUri = redirectUri;
        WristbandApplicationVanityDomain = wristbandApplicationVanityDomain;
        CustomApplicationLoginPageUrl = customApplicationLoginPageUrl;
        DangerouslyDisableSecureCookies = dangerouslyDisableSecureCookies;
        ParseTenantFromRootDomain = parseTenantFromRootDomain;
        Scopes = scopes;
        IsApplicationCustomDomainActive = isApplicationCustomDomainActive;
        TokenExpirationBuffer = tokenExpirationBuffer;
        AutoConfigureEnabled = autoConfigureEnabled;
    }

    /// <summary>
    /// Gets or sets whether the SDK should automatically configure some settings by calling the Wristband SDK Auto-Configuration Endpoint.
    /// Any manually provided configurations will take precedence over the configs returned from the endpoint.
    /// Auto-configure is enabled by default. When disabled, manual configurations must be provided, or an error will be thrown.
    /// </summary>
    public bool? AutoConfigureEnabled { get; set; } = true;

    /// <summary>
    /// Gets or sets the client ID for the application.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret for the application.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the custom application login (tenant discovery) page URL if you are self-hosting the application login/tenant discovery UI.
    /// </summary>
    public string? CustomApplicationLoginPageUrl { get; set; }

    /// <summary>
    /// Gets or sets whether to disable the "Secure" cookie attribute. This should only be set to true in local development.
    /// </summary>
    public bool? DangerouslyDisableSecureCookies { get; set; } = false;

    /// <summary>
    /// Gets or sets whether an application-level custom domain is active for the Wristband application.
    /// </summary>
    public bool? IsApplicationCustomDomainActive { get; set; }

    /// <summary>
    /// Gets or sets the secret used for encryption and decryption of login state cookies. It should be 32 or more characters long.
    /// </summary>
    public string? LoginStateSecret { get; set; }

    /// <summary>
    /// Gets or sets the URL for initiating the login request.
    /// </summary>
    public string? LoginUrl { get; set; }

    /// <summary>
    /// Gets or sets the redirect URI for callback after authentication.
    /// </summary>
    public string? RedirectUri { get; set; }

    /// <summary>
    /// Gets or sets the root domain for your application.
    /// </summary>
    public string? ParseTenantFromRootDomain { get; set; }

    /// <summary>
    /// Gets or sets the list of scopes required for authentication.
    /// </summary>
    public List<string>? Scopes { get; set; } = new List<string>();

    /// <summary>
    /// Gets or sets the buffer time (in seconds) to subtract from the access token’s expiration time.
    /// </summary>
    public int? TokenExpirationBuffer { get; set; } = 60;

    /// <summary>
    /// Gets or sets the vanity domain of the Wristband application.
    /// </summary>
    public string? WristbandApplicationVanityDomain { get; set; }
}
