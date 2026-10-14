using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <inheritdoc cref="IWristbandAuthService" />
public class WristbandAuthService : IWristbandAuthService
{
    private const string LoginRequiredError = "login_required";
    private static readonly TimeSpan LoginStateMaxAge = TimeSpan.FromHours(1);
    private static readonly TimeSpan LoginStateClockSkew = TimeSpan.FromMinutes(1);

    private readonly IWristbandApiClient _wristbandApiClient;
    private readonly ILoginStateHandler _loginStateHandler;
    private readonly ConfigResolver _configResolver;

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthService"/> class for production use.
    /// This constructor validates and configures the necessary settings for authentication.
    /// </summary>
    /// <param name="authConfig">The <see cref="WristbandAuthConfig"/> object containing authentication settings.</param>
    /// <exception cref="ArgumentException">Thrown if any required configuration values are missing or invalid.</exception>
    public WristbandAuthService(WristbandAuthConfig authConfig)
        : this(authConfig, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthService"/> class.
    /// This constructor validates and configures the necessary settings for authentication.
    /// This constructor is useful for testing, allowing the injection of a custom <see cref="HttpClient"/>.
    /// </summary>
    /// <param name="authConfig">The <see cref="WristbandAuthConfig"/> object containing authentication settings.</param>
    /// <param name="httpClientFactory">Optional external HTTP client factory. If not provided, an internal factory will be used.</param>
    /// <exception cref="ArgumentException">Thrown if any required configuration values are missing or invalid.</exception>
    public WristbandAuthService(WristbandAuthConfig authConfig, IHttpClientFactory? httpClientFactory = null)
    {
        // Create a client using the factory - validation happens inside the factory
        _wristbandApiClient = new WristbandApiClient(authConfig, httpClientFactory);
        _configResolver = new ConfigResolver(authConfig, _wristbandApiClient);
        _loginStateHandler = new LoginStateHandler();
    }

    /// <summary>
    /// Implements <see cref="IWristbandAuthService.Discover"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task Discover()
    {
        if (!_configResolver.GetAutoConfigureEnabled())
        {
            throw new WristbandError(
                "sdk_config_error",
                "Cannot preload configs when AutoConfigureEnabled is false. Set AutoConfigureEnabled to true.");
        }

        await _configResolver.PreloadConfig();
    }

    /// <summary>
    /// Implements <see cref="IWristbandAuthService.Login"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<string> Login(HttpContext context, LoginConfig? loginConfig)
    {
        if (loginConfig == null)
        {
            loginConfig = new LoginConfig();
        }

        var response = context.Response;
        response.Headers.Append("Cache-Control", "no-store");
        response.Headers.Append("Pragma", "no-cache");

        // Fetch our SDK configs using the ConfigResolver
        var applicationAuthorizationRequestsEnabled = await _configResolver.GetApplicationAuthorizationRequestsEnabled();
        var clientId = _configResolver.GetClientId();
        var customApplicationLoginPageUrl = await _configResolver.GetCustomApplicationLoginPageUrl();
        var dangerouslyDisableSecureCookies = _configResolver.GetDangerouslyDisableSecureCookies();
        var isApplicationCustomDomainActive = await _configResolver.GetIsApplicationCustomDomainActive();
        var loginStateSecret = _configResolver.GetLoginStateSecret();
        var parseTenantFromRootDomain = await _configResolver.GetParseTenantFromRootDomain();
        var redirectUri = await _configResolver.GetRedirectUri();
        var scopes = _configResolver.GetScopes();
        var wristbandApplicationVanityDomain = _configResolver.GetWristbandApplicationVanityDomain();

        // Determine which domain-related values are present as it will be needed for the authorize URL.
        // An invalid tenant custom domain is skipped over rather than failing the login, so resolution
        // falls through to the next domain in the precedence order below.
        var tenantCustomDomain = await ResolveValidTenantCustomDomainParam(context);
        var tenantName = ResolveTenantName(context, parseTenantFromRootDomain);
        var defaultTenantCustomDomain = loginConfig.DefaultTenantCustomDomain ?? string.Empty;
        var defaultTenantName = loginConfig.DefaultTenantName ?? string.Empty;

        var resolvedReturnUrl = ResolveReturnUrl(context, loginConfig.ReturnUrl);
        var isTenantUnresolved = string.IsNullOrEmpty(tenantCustomDomain) &&
            string.IsNullOrEmpty(tenantName) &&
            string.IsNullOrEmpty(defaultTenantCustomDomain) &&
            string.IsNullOrEmpty(defaultTenantName);

        // In the event we cannot determine either a tenant custom domain or subdomain, and app-level authorization
        // requests are disabled, send the user to the app-level login page.
        if (isTenantUnresolved && !applicationAuthorizationRequestsEnabled)
        {
            var apploginUrl = !string.IsNullOrEmpty(customApplicationLoginPageUrl)
                ? customApplicationLoginPageUrl : $"https://{wristbandApplicationVanityDomain}/login";
            var stateParam = !string.IsNullOrEmpty(resolvedReturnUrl)
                ? $"&state={Uri.EscapeDataString(resolvedReturnUrl)}"
                : string.Empty;
            return await Task.FromResult($"{apploginUrl}?client_id={clientId}{stateParam}");
        }

        // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
        var customState = loginConfig.CustomState != null && loginConfig.CustomState.Keys.Any()
            ? loginConfig.CustomState
            : null;

        var loginState = _loginStateHandler.CreateLoginState(context, redirectUri, resolvedReturnUrl, customState);

        var cookieDomain = GetLoginStateCookieDomain(applicationAuthorizationRequestsEnabled, parseTenantFromRootDomain);
        _loginStateHandler.CreateLoginStateCookie(context, loginState, loginStateSecret, dangerouslyDisableSecureCookies, cookieDomain);

        // Create the Wristband Authorize Endpoint URL which the user will get redirected to.
        var queryParams = new Dictionary<string, string>
        {
            { "client_id", clientId },
            { "redirect_uri", redirectUri },
            { "response_type", "code" },
            { "state", loginState.State },
            { "scope", string.Join(" ", scopes) },
            { "code_challenge", CreateCodeChallenge(loginState.CodeVerifier) },
            { "code_challenge_method", "S256" },
            { "nonce", _loginStateHandler.GenerateRandomString(32) },
        };

        // Optionally add login_hint query parameter if it was included in the login request.
        var loginHintValues = context.Request.Query["login_hint"];
        if (loginHintValues.Count > 1)
        {
            throw new ArgumentException("More than one [login_hint] query parameter was encountered");
        }

        var loginHint = loginHintValues.FirstOrDefault();
        if (!string.IsNullOrEmpty(loginHint))
        {
            queryParams["login_hint"] = loginHint;
        }

        // Optionally add idp_hint query parameter if it was included in the login request.
        var idpHintValues = context.Request.Query["idp_hint"];
        if (idpHintValues.Count > 1)
        {
            throw new ArgumentException("More than one [idp_hint] query parameter was encountered");
        }

        var idpHint = idpHintValues.FirstOrDefault();
        if (!string.IsNullOrEmpty(idpHint))
        {
            queryParams["idp_hint"] = idpHint;
        }

        var separator = isApplicationCustomDomainActive ? '.' : '-';
        var queryString = string.Join("&", queryParams
            .Where(p => p.Value != null)
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));

        // When no tenant can be resolved, send users to the app-level Authorize Endpoint with a login state cookie
        // instead of going to the app-level login page. Wristband handles tenant discovery within that same flow.
        if (isTenantUnresolved)
        {
            return $"https://{wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?{queryString}";
        }

        // Domain priority order resolution:
        // 1)  tenant_custom_domain query param
        // 2a) tenant subdomain
        // 2b) tenant_name query param
        // 3)  defaultTenantCustomDomain login config
        // 4)  defaultTenantName login config
        if (!string.IsNullOrEmpty(tenantCustomDomain))
        {
            return await Task.FromResult($"https://{tenantCustomDomain}/api/v1/oauth2/authorize?{queryString}");
        }

        if (!string.IsNullOrEmpty(tenantName))
        {
            return await Task.FromResult($"https://{tenantName}{separator}{wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?{queryString}");
        }

        if (!string.IsNullOrEmpty(defaultTenantCustomDomain))
        {
            return await Task.FromResult($"https://{defaultTenantCustomDomain}/api/v1/oauth2/authorize?{queryString}");
        }

        return await Task.FromResult($"https://{defaultTenantName}{separator}{wristbandApplicationVanityDomain}/api/v1/oauth2/authorize?{queryString}");
    }

    /// <summary>
    /// Implements <see cref="IWristbandAuthService.Callback"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<CallbackResult> Callback(HttpContext context)
    {
        context.Response.Headers.Append("Cache-Control", "no-store");
        context.Response.Headers.Append("Pragma", "no-cache");

        // Fetch our SDK configs using the ConfigResolver
        var applicationAuthorizationRequestsEnabled = await _configResolver.GetApplicationAuthorizationRequestsEnabled();
        var dangerouslyDisableSecureCookies = _configResolver.GetDangerouslyDisableSecureCookies();
        var loginStateSecret = _configResolver.GetLoginStateSecret();
        var loginUrl = await _configResolver.GetLoginUrl();
        var parseTenantFromRootDomain = await _configResolver.GetParseTenantFromRootDomain();
        var tokenExpirationBuffer = _configResolver.GetTokenExpirationBuffer();

        // Ensure that the request has a query string present
        var query = context.Request.Query;
        if (query == null || !query.Any())
        {
            throw new InvalidOperationException("The callback request did not have a query string.");
        }

        // Get and validate query parameters
        var paramState = query["state"].FirstOrDefault();
        var code = query["code"].FirstOrDefault();
        var error = query["error"].FirstOrDefault();
        var errorDescription = query["error_description"].FirstOrDefault();

        // An invalid tenant custom domain is skipped over rather than failing the callback.
        var tenantCustomDomainParam = await ResolveValidTenantCustomDomainParam(context);

        if (string.IsNullOrEmpty(paramState) || query["state"].Count > 1)
        {
            throw new ArgumentException("Invalid query parameter [state] passed from Wristband during callback");
        }

        // Resolve and validate the tenant name
        var resolvedTenantName = ResolveTenantName(context, parseTenantFromRootDomain);
        if (string.IsNullOrEmpty(resolvedTenantName))
        {
            var errorCode = !string.IsNullOrEmpty(parseTenantFromRootDomain)
                ? "missing_tenant_subdomain"
                : "missing_tenant_name";
            var errorMessage = !string.IsNullOrEmpty(parseTenantFromRootDomain)
                ? "Callback request URL is missing a tenant subdomain"
                : "Callback request is missing the [tenant_name] query parameter from Wristband";
            throw new WristbandError(errorCode, errorMessage);
        }

        // Construct the tenant login URL in the event we have to redirect to the login endpoint
        string tenantLoginUrl;
        if (!string.IsNullOrEmpty(parseTenantFromRootDomain))
        {
            tenantLoginUrl = loginUrl.Replace(TenantUrlUtils.TenantNamePlaceholder, resolvedTenantName);
        }
        else
        {
            tenantLoginUrl = $"{loginUrl}?tenant_name={resolvedTenantName}";
        }

        if (!string.IsNullOrEmpty(tenantCustomDomainParam))
        {
            var querySeparator = !string.IsNullOrEmpty(parseTenantFromRootDomain) ? "?" : "&";
            tenantLoginUrl = $"{tenantLoginUrl}{querySeparator}tenant_custom_domain={tenantCustomDomainParam}";
        }

        // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
        var cookieDomain = GetLoginStateCookieDomain(applicationAuthorizationRequestsEnabled, parseTenantFromRootDomain);
        var loginStateCookie = _loginStateHandler.GetAndClearLoginStateCookie(context, dangerouslyDisableSecureCookies, cookieDomain);
        if (string.IsNullOrEmpty(loginStateCookie))
        {
            return new CallbackResult(
                CallbackResultType.RedirectRequired,
                null,
                tenantLoginUrl,
                CallbackFailureReason.MissingLoginState);
        }

        // Check for any invalid login or mismatched login state. A cookie that cannot be decrypted (tampered,
        // malformed, or encrypted with a different secret) or is older than its lifetime can't be trusted.
        var loginState = TryDecryptLoginState(loginStateCookie, loginStateSecret);
        if (loginState == null || paramState != loginState.State || IsLoginStateExpired(loginState))
        {
            return new CallbackResult(
                CallbackResultType.RedirectRequired,
                null,
                tenantLoginUrl,
                CallbackFailureReason.InvalidLoginState);
        }

        // Check for any error code conditions
        if (!string.IsNullOrEmpty(error))
        {
            if (!error.Equals(LoginRequiredError, StringComparison.OrdinalIgnoreCase))
            {
                throw new WristbandError(error, errorDescription);
            }

            return new CallbackResult(
                CallbackResultType.RedirectRequired,
                null,
                tenantLoginUrl,
                CallbackFailureReason.LoginRequired);
        }

        // Exchange the authorization code for tokens
        if (string.IsNullOrEmpty(code))
        {
            throw new ArgumentException("Invalid query parameter [code] passed from Wristband during callback");
        }

        try
        {
            // Exchange the authorization code for tokens
            var tokenResponse = await _wristbandApiClient.GetTokens(code, loginState.RedirectUri, loginState.CodeVerifier);

            // Get the UserInfo using the access token
            var userInfo = await _wristbandApiClient.GetUserinfo(tokenResponse.AccessToken);

            var expiresIn = (tokenResponse?.ExpiresIn ?? 0) - tokenExpirationBuffer;
            var expiresAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() + (expiresIn * 1000);

            // Prevent open redirects by validating the return URL against allowed hosts.
            var validatedReturnUrl = TenantUrlUtils.ValidateReturnUrl(
                loginState.ReturnUrl,
                string.IsNullOrEmpty(context.Request.Scheme) ? "https" : context.Request.Scheme,
                context.Request.Host.Value ?? string.Empty,
                resolvedTenantName,
                applicationAuthorizationRequestsEnabled,
                parseTenantFromRootDomain);

            var callbackData = new CallbackData(
                tokenResponse?.AccessToken ?? string.Empty,
                expiresAt,
                expiresIn,
                tokenResponse?.IdToken ?? string.Empty,
                tokenResponse?.RefreshToken,
                userInfo,
                resolvedTenantName,
                string.IsNullOrEmpty(tenantCustomDomainParam) ? null : tenantCustomDomainParam,
                loginState.CustomState,
                validatedReturnUrl);
            return new CallbackResult(CallbackResultType.Completed, callbackData, null);
        }
        catch (InvalidGrantError)
        {
            // Handle "invalid_grant" errors gracefully
            return new CallbackResult(
                CallbackResultType.RedirectRequired,
                null,
                tenantLoginUrl,
                CallbackFailureReason.InvalidGrant);
        }
    }

    /// <summary>
    /// Implements <see cref="IWristbandAuthService.Logout"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<string> Logout(HttpContext context, LogoutConfig? logoutConfig)
    {
        context.Response.Headers.Append("Cache-Control", "no-store");
        context.Response.Headers.Append("Pragma", "no-cache");

        if (logoutConfig == null)
        {
            logoutConfig = new LogoutConfig();
        }

        if (!string.IsNullOrEmpty(logoutConfig.State) && logoutConfig.State.Length > 512)
        {
            throw new ArgumentException("The [state] logout config cannot exceed 512 characters.");
        }

        // Fetch our SDK configs using the ConfigResolver
        var applicationAuthorizationRequestsEnabled = await _configResolver.GetApplicationAuthorizationRequestsEnabled();
        var clientId = _configResolver.GetClientId();
        var customApplicationLoginPageUrl = await _configResolver.GetCustomApplicationLoginPageUrl();
        var isApplicationCustomDomainActive = await _configResolver.GetIsApplicationCustomDomainActive();
        var parseTenantFromRootDomain = await _configResolver.GetParseTenantFromRootDomain();
        var wristbandApplicationVanityDomain = _configResolver.GetWristbandApplicationVanityDomain();

        if (!string.IsNullOrWhiteSpace(logoutConfig.RefreshToken))
        {
            await _wristbandApiClient.RevokeRefreshToken(logoutConfig.RefreshToken);
        }

        var tenantName = ResolveTenantName(context, parseTenantFromRootDomain);

        // An invalid tenant custom domain is skipped over rather than failing the logout, so
        // resolution falls through to the next domain in the precedence order below.
        var tenantCustomDomainParam = await ResolveValidTenantCustomDomainParam(context);
        var redirectUrl = !string.IsNullOrEmpty(logoutConfig.RedirectUrl) ? $"&redirect_url={logoutConfig.RedirectUrl}" : string.Empty;
        var state = !string.IsNullOrEmpty(logoutConfig.State) ? $"&state={Uri.EscapeDataString(logoutConfig.State)}" : string.Empty;

        // The client ID is always required by the Wristband Logout Endpoint.
        var logoutPath = $"/api/v1/logout?client_id={clientId}{redirectUrl}{state}";
        string separator = isApplicationCustomDomainActive ? "." : "-";

        // Domain priority order resolution:
        // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
        if (!string.IsNullOrWhiteSpace(logoutConfig.TenantCustomDomain))
        {
            return $"https://{logoutConfig.TenantCustomDomain}{logoutPath}";
        }

        // 2) If the LogoutConfig has a tenant name defined, then use that.
        if (!string.IsNullOrWhiteSpace(logoutConfig.TenantName))
        {
            return $"https://{logoutConfig.TenantName}{separator}{wristbandApplicationVanityDomain}{logoutPath}";
        }

        // 3) If the tenant_custom_domain query param exists, then use that.
        if (!string.IsNullOrEmpty(tenantCustomDomainParam))
        {
            return $"https://{tenantCustomDomainParam}{logoutPath}";
        }

        // 4a) If tenant subdomains are enabled, get the tenant name from the host.
        // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_name query param.
        if (!string.IsNullOrEmpty(tenantName))
        {
            return $"https://{tenantName}{separator}{wristbandApplicationVanityDomain}{logoutPath}";
        }

        // 5) First try falling back to the logout redirect URL (if the LogoutConfig has it) when tenant cannot be resolved.
        if (!string.IsNullOrEmpty(logoutConfig.RedirectUrl))
        {
            return logoutConfig.RedirectUrl;
        }

        // 6) If app-level authorization requests are enabled, then redirect to the appropriate app-level Login Endpoint
        // to start a new app-level Authorize Endpoint flow.
        if (applicationAuthorizationRequestsEnabled)
        {
            var loginUrl = await _configResolver.GetLoginUrl();
            return loginUrl.Contains(TenantUrlUtils.TenantNamePlaceholder)
                ? await _configResolver.GetFallbackLoginUrl()
                : loginUrl;
        }

        // 7a) If a custom page URL is set, fallback to that Application-Level Login when tenant cannot be resolved.
        // 7b) Finally, fallback to the Wristband-hosted Application-Level Login Page when tenant cannot be resolved.
        var appLoginUrl = !string.IsNullOrEmpty(customApplicationLoginPageUrl)
            ? customApplicationLoginPageUrl
            : $"https://{wristbandApplicationVanityDomain}/login";
        return $"{appLoginUrl}?client_id={clientId}";
    }

    /// <summary>
    /// Implements <see cref="IWristbandAuthService.RefreshTokenIfExpired"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<TokenData?> RefreshTokenIfExpired(string refreshToken, long expiresAt)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            throw new ArgumentException("Refresh token must be a valid string");
        }

        if (expiresAt < 0)
        {
            throw new ArgumentException("The expiresAt field must be a positive integer");
        }

        if (!IsExpired(expiresAt))
        {
            return null;
        }

        // Fetch our SDK configs using the ConfigResolver
        var tokenExpirationBuffer = _configResolver.GetTokenExpirationBuffer();

        // Retrying transient failures is handled by the API client, so this makes a single call.
        // Retrying here as well would compound the two policies into far more attempts than intended.
        var tokenResponse = await _wristbandApiClient.RefreshToken(refreshToken);
        var newExpiresIn = (tokenResponse?.ExpiresIn ?? 0) - tokenExpirationBuffer;
        var newExpiresAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() + (newExpiresIn * 1000);
        return new TokenData(
            tokenResponse?.AccessToken ?? string.Empty,
            newExpiresAt,
            newExpiresIn,
            tokenResponse?.IdToken ?? string.Empty,
            tokenResponse?.RefreshToken);
    }

    // ========================================
    //  PRIVATE METHODS
    // ========================================
    private static string CreateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        var base64 = Convert.ToBase64String(challengeBytes);
        return base64.Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    private static string? GetLoginStateCookieDomain(bool applicationAuthorizationRequestsEnabled, string parseTenantFromRootDomain)
    {
        // With app-level authorization requests and tenant subdomains, the login can start on the root domain and
        // finish on a tenant subdomain, so the login state cookie must be readable across both.
        return applicationAuthorizationRequestsEnabled && !string.IsNullOrEmpty(parseTenantFromRootDomain)
            ? $".{parseTenantFromRootDomain}"
            : null;
    }

    private static bool IsLoginStateExpired(LoginState loginState)
    {
        var createdAt = DateTimeOffset.FromUnixTimeMilliseconds(loginState.CreatedAt);
        var now = DateTimeOffset.UtcNow;
        return now - createdAt > LoginStateMaxAge + LoginStateClockSkew || createdAt - now > LoginStateClockSkew;
    }

    private static bool IsExpired(long expiresAt)
    {
        var currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        return currentTime >= expiresAt;
    }

    private static string ParseTenantSubdomain(string host, string parseTenantFromRootDomain)
    {
        if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(parseTenantFromRootDomain))
        {
            return string.Empty;
        }

        // Strip port, if present
        var hostname = host.Split(':')[0];

        // Attempt to strip out subdomain and ensure the root domain matches SDK configuration
        var dotIndex = host.IndexOf('.');
        if (dotIndex < 0)
        {
            return string.Empty;
        }

        var rootDomain = hostname.Substring(dotIndex + 1);
        if (rootDomain != parseTenantFromRootDomain)
        {
            return string.Empty;
        }

        return hostname.Substring(0, dotIndex);
    }

    private static string ResolveTenantName(HttpContext context, string parseTenantFromRootDomain)
    {
        if (!string.IsNullOrEmpty(parseTenantFromRootDomain))
        {
            var host = context.Request.Host.Value ?? string.Empty;
            return ParseTenantSubdomain(host, parseTenantFromRootDomain);
        }

        var tenantNameParam = context.Request.Query["tenant_name"].FirstOrDefault();

        if (!string.IsNullOrEmpty(tenantNameParam) && tenantNameParam.Contains(","))
        {
            throw new ArgumentException("More than one [tenant_name] query parameter was encountered");
        }

        // Return the tenant name if it exists, otherwise return an empty string
        return tenantNameParam ?? string.Empty;
    }

    private static string ResolveTenantCustomDomainParam(HttpContext context)
    {
        var tenantCustomDomainParam = context.Request.Query["tenant_custom_domain"].FirstOrDefault();

        if (!string.IsNullOrEmpty(tenantCustomDomainParam) && tenantCustomDomainParam.Contains(","))
        {
            throw new ArgumentException("More than one [tenant_custom_domain] query parameter was encountered");
        }

        return tenantCustomDomainParam ?? string.Empty;
    }

    private static string? ResolveReturnUrl(HttpContext context, string? configReturnUrl)
    {
        var returnUrlParams = context.Request.Query["return_url"];

        if (returnUrlParams.Count > 1)
        {
            throw new ArgumentException("More than one [return_url] query parameter was encountered");
        }

        var queryReturnUrl = returnUrlParams.FirstOrDefault();

        // LoginConfig takes precedence over query parameter
        var resolvedReturnUrl = configReturnUrl ?? queryReturnUrl;

        if (!string.IsNullOrEmpty(resolvedReturnUrl) && resolvedReturnUrl.Length > 450)
        {
            Console.WriteLine($"Return URL exceeds 450 characters: {resolvedReturnUrl}");
            return null; // Ignore if too long
        }

        return resolvedReturnUrl;
    }

    private LoginState? TryDecryptLoginState(string loginStateCookie, string loginStateSecret)
    {
        try
        {
            return _loginStateHandler.DecryptLoginState(loginStateCookie, loginStateSecret);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Resolves the tenant_custom_domain query parameter to itself when it is verified and belongs to
    /// your Wristband application, and to an empty string otherwise so that the caller skips over it
    /// and falls through to the next domain in its resolution precedence order.
    /// </summary>
    /// <remarks>
    /// Validation only applies to domains supplied via the tenant_custom_domain query parameter, which
    /// is attacker-controllable. Domains set directly in configuration by the developer are trusted and
    /// are not validated.
    /// </remarks>
    /// <param name="context">The current HTTP context.</param>
    /// <returns>A task that represents the asynchronous operation and contains the validated domain, or an empty string.</returns>
    private async Task<string> ResolveValidTenantCustomDomainParam(HttpContext context)
    {
        var tenantCustomDomainParam = ResolveTenantCustomDomainParam(context);
        if (string.IsNullOrEmpty(tenantCustomDomainParam))
        {
            return string.Empty;
        }

        var isValid = await _wristbandApiClient.ValidateTenantCustomDomain(tenantCustomDomainParam);
        return isValid ? tenantCustomDomainParam : string.Empty;
    }
}
