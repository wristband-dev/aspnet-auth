using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <inheritdoc cref="IWristbandAuthService" />
public class WristbandAuthService : IWristbandAuthService
{
    private const string TenantDomainPlaceholder = "{tenant_domain}";
    private const string TenantNamePlaceholder = "{tenant_name}";
    private const string LoginRequiredError = "login_required";
    private const int TokenRefreshRetryAttempts = 3;
    private const int DelayBetweenRefreshAttempts = 100; // 100ms

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
        var tenantCustomDomain = ResolveTenantCustomDomainParam(context);
        var tenantName = ResolveTenantName(context, parseTenantFromRootDomain);
        var defaultTenantCustomDomain = loginConfig.DefaultTenantCustomDomain ?? string.Empty;
        var defaultTenantName = loginConfig.DefaultTenantName ?? string.Empty;

        var resolvedReturnUrl = ResolveReturnUrl(context, loginConfig.ReturnUrl);

        // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
        if (string.IsNullOrEmpty(tenantCustomDomain) &&
            string.IsNullOrEmpty(tenantName) &&
            string.IsNullOrEmpty(defaultTenantCustomDomain) &&
            string.IsNullOrEmpty(defaultTenantName))
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

        _loginStateHandler.CreateLoginStateCookie(context, loginState, loginStateSecret, dangerouslyDisableSecureCookies);

        // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
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
            { "login_hint", context.Request.Query["login_hint"].FirstOrDefault() ?? string.Empty },
        };

        var separator = isApplicationCustomDomainActive ? '.' : '-';
        var queryString = string.Join("&", queryParams
            .Where(p => p.Value != null)
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));

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
        var tenantCustomDomainParam = query["tenant_custom_domain"].FirstOrDefault();

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
            // Replace both {tenant_name} and {tenant_domain} for backwards compatibility
            tenantLoginUrl = loginUrl
                .Replace(TenantNamePlaceholder, resolvedTenantName)
                .Replace(TenantDomainPlaceholder, resolvedTenantName);
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
        var loginStateCookie = _loginStateHandler.GetAndClearLoginStateCookie(context, dangerouslyDisableSecureCookies);
        if (string.IsNullOrEmpty(loginStateCookie))
        {
            return new CallbackResult(
                CallbackResultType.RedirectRequired,
                null,
                tenantLoginUrl,
                CallbackFailureReason.MissingLoginState);
        }

        // Check for any invalid login or mismatched login state
        var loginState = _loginStateHandler.DecryptLoginState(loginStateCookie, loginStateSecret);
        if (loginState == null || paramState != loginState.State)
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
            var callbackData = new CallbackData(
                tokenResponse?.AccessToken ?? string.Empty,
                expiresAt,
                expiresIn,
                tokenResponse?.IdToken ?? string.Empty,
                tokenResponse?.RefreshToken,
                userInfo,
                resolvedTenantName,
                tenantCustomDomainParam,
                loginState.CustomState,
                loginState.ReturnUrl);
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
        var tenantCustomDomainParam = ResolveTenantCustomDomainParam(context);
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

        // Fallback to app login URL (or custom logout redirect URL) if tenant cannot be determined
        var appLoginUrl = !string.IsNullOrEmpty(customApplicationLoginPageUrl)
            ? customApplicationLoginPageUrl
            : $"https://{wristbandApplicationVanityDomain}/login";
        return !string.IsNullOrEmpty(logoutConfig.RedirectUrl)
                ? logoutConfig.RedirectUrl
                : $"{appLoginUrl}?client_id={clientId}";
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

        // Make 3 attempts to refresh the token
        for (int attempt = 1; attempt <= TokenRefreshRetryAttempts; attempt++)
        {
            try
            {
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
            catch (WristbandError ex)
            {
                // Bail the process on invalid refresh token
                if (ex.Error == "invalid_refresh_token" || attempt == TokenRefreshRetryAttempts)
                {
                    throw;
                }

                await Task.Delay(TokenRefreshRetryAttempts);
            }
            catch (Exception)
            {
                if (attempt == TokenRefreshRetryAttempts)
                {
                    throw;
                }

                await Task.Delay(DelayBetweenRefreshAttempts);
            }
        }

        throw new InvalidOperationException("Invalid state reached during refresh token operation.");
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
}
