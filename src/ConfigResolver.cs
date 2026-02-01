namespace Wristband.AspNet.Auth;

/// <summary>
/// Handles configuration resolution for Wristband authentication, supporting both manual configuration
/// and auto-configuration from the Wristband SDK Configuration Endpoint.
/// </summary>
internal class ConfigResolver
{
    private const string TenantDomainPlaceholder = "{tenant_domain}";
    private const string TenantNamePlaceholder = "{tenant_name}";
    private const int DefaultTokenExpirationBuffer = 60; // 60 seconds
    private const int MaxFetchAttempts = 3;
    private const int AttemptDelayMs = 100; // 100 milliseconds
    private static readonly List<string> DefaultScopes = new List<string> { "openid", "offline_access", "email" };

    private readonly WristbandAuthConfig _authConfig;
    private readonly IWristbandApiClient _wristbandApiClient;
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private SdkConfiguration? _cachedSdkConfig;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConfigResolver"/> class.
    /// </summary>
    /// <param name="authConfig">The authentication configuration.</param>
    /// <param name="wristbandApiClient">The Wristband API client for fetching SDK configuration.</param>
    public ConfigResolver(WristbandAuthConfig authConfig, IWristbandApiClient wristbandApiClient)
    {
        _authConfig = authConfig ?? throw new ArgumentNullException(nameof(authConfig));
        _wristbandApiClient = wristbandApiClient ?? throw new ArgumentNullException(nameof(wristbandApiClient));

        // Always validate required configurations
        ValidateRequiredAuthConfigs();

        if (GetAutoConfigureEnabled())
        {
            // Only validate manually provided values when auto-configure is enabled
            ValidatePartialUrlAuthConfigs();
        }
        else
        {
            // Validate all configurations if auto-configure is disabled
            ValidateStrictUrlAuthConfigs();
        }
    }

    /// <summary>
    /// Forces loading and caching of all auto-configurable fields.
    /// This will trigger the API call and cache the results.
    /// Any validation errors will be thrown here (fail-fast).
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="WristbandError">Thrown when auto-configure is disabled or configuration fails.</exception>
    public async Task PreloadConfig()
    {
        if (!GetAutoConfigureEnabled())
        {
            throw new WristbandError(
                "config_error",
                "Cannot preload configs when AutoConfigureEnabled is false. Set AutoConfigureEnabled to true.");
        }

        await LoadSdkConfig();
    }

    /// <summary>
    /// Gets the client ID from the authentication configuration.
    /// </summary>
    /// <returns>The client ID.</returns>
    public string GetClientId()
    {
        return _authConfig.ClientId ?? throw new InvalidOperationException("ClientId is required");
    }

    /// <summary>
    /// Gets the client secret from the authentication configuration.
    /// </summary>
    /// <returns>The client secret.</returns>
    public string GetClientSecret()
    {
        return _authConfig.ClientSecret ?? throw new InvalidOperationException("ClientSecret is required");
    }

    /// <summary>
    /// Gets the login state secret, defaulting to client secret if not specified.
    /// </summary>
    /// <returns>The login state secret.</returns>
    public string GetLoginStateSecret()
    {
        return _authConfig.LoginStateSecret ?? GetClientSecret();
    }

    /// <summary>
    /// Gets the Wristband application vanity domain.
    /// </summary>
    /// <returns>The Wristband application vanity domain.</returns>
    public string GetWristbandApplicationVanityDomain()
    {
        return _authConfig.WristbandApplicationVanityDomain ??
               throw new InvalidOperationException("WristbandApplicationVanityDomain is required");
    }

    /// <summary>
    /// Gets whether secure cookies are disabled (for development only).
    /// </summary>
    /// <returns>True if secure cookies are disabled; otherwise, false.</returns>
    public bool GetDangerouslyDisableSecureCookies()
    {
        return _authConfig.DangerouslyDisableSecureCookies.GetValueOrDefault(false);
    }

    /// <summary>
    /// Gets the authentication scopes, defaulting to standard OpenID scopes.
    /// </summary>
    /// <returns>A list of authentication scopes.</returns>
    public List<string> GetScopes()
    {
        return _authConfig.Scopes?.Any() == true ? _authConfig.Scopes : DefaultScopes;
    }

    /// <summary>
    /// Gets whether auto-configuration is enabled (true by default).
    /// </summary>
    /// <returns>True if auto-configuration is enabled; otherwise, false.</returns>
    public bool GetAutoConfigureEnabled()
    {
        return _authConfig.AutoConfigureEnabled.GetValueOrDefault(true);
    }

    /// <summary>
    /// Gets the token expiration buffer in seconds.
    /// </summary>
    /// <returns>The token expiration buffer in seconds.</returns>
    public int GetTokenExpirationBuffer()
    {
        return _authConfig.TokenExpirationBuffer.GetValueOrDefault(DefaultTokenExpirationBuffer);
    }

    /// <summary>
    /// Gets the custom application login page URL.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation. The task result contains the custom application login page URL, or null if not configured.</returns>
    public async Task<string> GetCustomApplicationLoginPageUrl()
    {
        // 1. Check if manually provided in authConfig
        if (!string.IsNullOrEmpty(_authConfig.CustomApplicationLoginPageUrl))
        {
            return _authConfig.CustomApplicationLoginPageUrl;
        }

        // 2. If auto-configure is enabled, get from SDK config
        if (GetAutoConfigureEnabled())
        {
            var sdkConfig = await LoadSdkConfig();
            return sdkConfig.CustomApplicationLoginPageUrl ?? string.Empty;
        }

        // 3. Default fallback
        return string.Empty;
    }

    /// <summary>
    /// Gets whether the application custom domain is active.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation. The task result contains true if the application custom domain is active; otherwise, false.</returns>
    public async Task<bool> GetIsApplicationCustomDomainActive()
    {
        // 1. Check if manually provided in authConfig
        if (_authConfig.IsApplicationCustomDomainActive.HasValue)
        {
            return _authConfig.IsApplicationCustomDomainActive.Value;
        }

        // 2. If auto-configure is enabled, get from SDK config
        if (GetAutoConfigureEnabled())
        {
            var sdkConfig = await LoadSdkConfig();
            return sdkConfig.IsApplicationCustomDomainActive;
        }

        // 3. Default fallback
        return false;
    }

    /// <summary>
    /// Gets the login URL.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation. The task result contains the login URL.</returns>
    public async Task<string> GetLoginUrl()
    {
        // 1. Check if manually provided in authConfig
        if (!string.IsNullOrEmpty(_authConfig.LoginUrl))
        {
            return _authConfig.LoginUrl;
        }

        // 2. If auto-configure is enabled, get from SDK config
        if (GetAutoConfigureEnabled())
        {
            var sdkConfig = await LoadSdkConfig();
            return sdkConfig.LoginUrl;
        }

        // 3. This should not happen if validation is done properly
        throw new InvalidOperationException("LoginUrl must have a value");
    }

    /// <summary>
    /// Gets the root domain for parsing tenant subdomains.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation. The task result contains the root domain for parsing tenant subdomains, or null if not configured.</returns>
    public async Task<string> GetParseTenantFromRootDomain()
    {
        // 1. Check if manually provided in authConfig
        if (!string.IsNullOrEmpty(_authConfig.ParseTenantFromRootDomain))
        {
            return _authConfig.ParseTenantFromRootDomain;
        }

        // 2. If auto-configure is enabled, get from SDK config
        if (GetAutoConfigureEnabled())
        {
            var sdkConfig = await LoadSdkConfig();
            return sdkConfig.LoginUrlTenantDomainSuffix ?? string.Empty;
        }

        // 3. Default fallback
        return string.Empty;
    }

    /// <summary>
    /// Gets the redirect URI.
    /// </summary>
    /// <returns>A task that represents the asynchronous operation. The task result contains the redirect URI.</returns>
    public async Task<string> GetRedirectUri()
    {
        // 1. Check if manually provided in authConfig
        if (!string.IsNullOrEmpty(_authConfig.RedirectUri))
        {
            return _authConfig.RedirectUri;
        }

        // 2. If auto-configure is enabled, get from SDK config
        if (GetAutoConfigureEnabled())
        {
            var sdkConfig = await LoadSdkConfig();
            return sdkConfig.RedirectUri;
        }

        // 3. This should not happen if validation is done properly
        throw new InvalidOperationException("RedirectUri must have a value");
    }

    /// <summary>
    /// Checks if a URL contains either the tenant domain placeholder or tenant name placeholder.
    /// </summary>
    /// <param name="url">The URL to check.</param>
    /// <returns>True if the URL contains either placeholder; otherwise, false.</returns>
    private static bool ContainsTenantPlaceholder(string url)
    {
        return url.Contains(TenantDomainPlaceholder) || url.Contains(TenantNamePlaceholder);
    }

    private async Task<SdkConfiguration> LoadSdkConfig()
    {
        if (_cachedSdkConfig != null)
        {
            return _cachedSdkConfig;
        }

        await _semaphore.WaitAsync();

        try
        {
            if (_cachedSdkConfig != null)
            {
                return _cachedSdkConfig;
            }

            var config = await FetchSdkConfiguration();
            ValidateAllDynamicConfigs(config);
            _cachedSdkConfig = config; // Only cache on success
            return config;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task<SdkConfiguration> FetchSdkConfiguration()
    {
        Exception? lastError = null;

        for (int attempt = 1; attempt <= MaxFetchAttempts; attempt++)
        {
            try
            {
                return await _wristbandApiClient.GetSdkConfiguration();
            }
            catch (Exception error)
            {
                lastError = error;

                // Final attempt failed, throw the error
                if (attempt == MaxFetchAttempts)
                {
                    break;
                }

                // Wait before retrying
                await Task.Delay(AttemptDelayMs);
            }
        }

        throw new WristbandError(
            "sdk_config_error",
            $"Failed to fetch SDK configuration after {MaxFetchAttempts} attempts: {lastError?.Message ?? "Unknown error"}");
    }

    private void ValidateRequiredAuthConfigs()
    {
        if (string.IsNullOrWhiteSpace(_authConfig.ClientId))
        {
            throw new ArgumentException("The [ClientId] config must have a value.");
        }

        if (string.IsNullOrWhiteSpace(_authConfig.ClientSecret))
        {
            throw new ArgumentException("The [ClientSecret] config must have a value.");
        }

        if (!string.IsNullOrEmpty(_authConfig.LoginStateSecret) && _authConfig.LoginStateSecret.Length < 32)
        {
            throw new ArgumentException("The [LoginStateSecret] config must have a value of at least 32 characters.");
        }

        if (string.IsNullOrWhiteSpace(_authConfig.WristbandApplicationVanityDomain))
        {
            throw new ArgumentException("The [WristbandApplicationVanityDomain] config must have a value.");
        }

        if (_authConfig.TokenExpirationBuffer.HasValue && _authConfig.TokenExpirationBuffer.Value < 0)
        {
            throw new ArgumentException("The [TokenExpirationBuffer] config must be greater than or equal to 0.");
        }
    }

    private void ValidateStrictUrlAuthConfigs()
    {
        if (string.IsNullOrWhiteSpace(_authConfig.LoginUrl))
        {
            throw new ArgumentException("The [LoginUrl] config must have a value when auto-configure is disabled.");
        }

        if (string.IsNullOrWhiteSpace(_authConfig.RedirectUri))
        {
            throw new ArgumentException("The [RedirectUri] config must have a value when auto-configure is disabled.");
        }

        var hasRootDomain = !string.IsNullOrEmpty(_authConfig.ParseTenantFromRootDomain);
        var loginUrlHasToken = ContainsTenantPlaceholder(_authConfig.LoginUrl);
        var redirectUriHasToken = ContainsTenantPlaceholder(_authConfig.RedirectUri);

        if (hasRootDomain && !loginUrlHasToken)
        {
            throw new ArgumentException(
                $"The [LoginUrl] must contain the \"{TenantNamePlaceholder}\" token when using the [ParseTenantFromRootDomain] config.");
        }

        if (!hasRootDomain && loginUrlHasToken)
        {
            throw new ArgumentException(
                $"The [LoginUrl] cannot contain the \"{TenantNamePlaceholder}\" token when the [ParseTenantFromRootDomain] is absent.");
        }

        if (hasRootDomain && !redirectUriHasToken)
        {
            throw new ArgumentException(
                $"The [RedirectUri] must contain the \"{TenantNamePlaceholder}\" token when using the [ParseTenantFromRootDomain] config.");
        }

        if (!hasRootDomain && redirectUriHasToken)
        {
            throw new ArgumentException(
                $"The [RedirectUri] cannot contain the \"{TenantNamePlaceholder}\" token when the [ParseTenantFromRootDomain] is absent.");
        }
    }

    private void ValidatePartialUrlAuthConfigs()
    {
        var hasRootDomain = !string.IsNullOrEmpty(_authConfig.ParseTenantFromRootDomain);

        if (!string.IsNullOrEmpty(_authConfig.LoginUrl))
        {
            var hasToken = ContainsTenantPlaceholder(_authConfig.LoginUrl);
            if (hasRootDomain && !hasToken)
            {
                throw new ArgumentException(
                    $"The [LoginUrl] must contain the \"{TenantNamePlaceholder}\" token when using the [ParseTenantFromRootDomain] config.");
            }

            if (!hasRootDomain && hasToken)
            {
                throw new ArgumentException(
                    $"The [LoginUrl] cannot contain the \"{TenantNamePlaceholder}\" token when the [ParseTenantFromRootDomain] is absent.");
            }
        }

        if (!string.IsNullOrEmpty(_authConfig.RedirectUri))
        {
            var hasToken = ContainsTenantPlaceholder(_authConfig.RedirectUri);
            if (hasRootDomain && !hasToken)
            {
                throw new ArgumentException(
                    $"The [RedirectUri] must contain the \"{TenantNamePlaceholder}\" token when using the [ParseTenantFromRootDomain] config.");
            }

            if (!hasRootDomain && hasToken)
            {
                throw new ArgumentException(
                    $"The [RedirectUri] cannot contain the \"{TenantNamePlaceholder}\" token when the [ParseTenantFromRootDomain] is absent.");
            }
        }
    }

    private void ValidateAllDynamicConfigs(SdkConfiguration sdkConfiguration)
    {
        // Validate that required fields are present in the SDK config response
        if (string.IsNullOrEmpty(sdkConfiguration.LoginUrl))
        {
            throw new WristbandError("sdk_config_error", "SDK configuration response missing required field: LoginUrl");
        }

        if (string.IsNullOrEmpty(sdkConfiguration.RedirectUri))
        {
            throw new WristbandError("sdk_config_error", "SDK configuration response missing required field: RedirectUri");
        }

        // Use manual config values if provided, otherwise use SDK config values
        var loginUrl = _authConfig.LoginUrl ?? sdkConfiguration.LoginUrl;
        var redirectUri = _authConfig.RedirectUri ?? sdkConfiguration.RedirectUri;
        var parseTenantFromRootDomain = _authConfig.ParseTenantFromRootDomain ??
            sdkConfiguration.LoginUrlTenantDomainSuffix;

        var hasRootDomain = !string.IsNullOrEmpty(parseTenantFromRootDomain);
        var loginUrlHasToken = ContainsTenantPlaceholder(loginUrl);
        var redirectUriHasToken = ContainsTenantPlaceholder(redirectUri);

        if (hasRootDomain && !loginUrlHasToken)
        {
            throw new WristbandError(
                "config_validation_error",
                $"The resolved [LoginUrl] must contain the \"{TenantNamePlaceholder}\" token when using [ParseTenantFromRootDomain].");
        }

        if (!hasRootDomain && loginUrlHasToken)
        {
            throw new WristbandError(
                "config_validation_error",
                $"The resolved [LoginUrl] cannot contain the \"{TenantNamePlaceholder}\" token when [ParseTenantFromRootDomain] is absent.");
        }

        if (hasRootDomain && !redirectUriHasToken)
        {
            throw new WristbandError(
                "config_validation_error",
                $"The resolved [RedirectUri] must contain the \"{TenantNamePlaceholder}\" token when using [ParseTenantFromRootDomain].");
        }

        if (!hasRootDomain && redirectUriHasToken)
        {
            throw new WristbandError(
                "config_validation_error",
                $"The resolved [RedirectUri] cannot contain the \"{TenantNamePlaceholder}\" token when [ParseTenantFromRootDomain] is absent.");
        }
    }
}
