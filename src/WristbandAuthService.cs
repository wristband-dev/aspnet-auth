using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <inheritdoc cref="IWristbandAuthService" />
public class WristbandAuthService : IWristbandAuthService
{
    private const string TenantDomainToken = "{tenant_domain}";
    private const string LoginRequiredError = "login_required";
    private const int DefaultTokenExpirationBuffer = 60; // 60s
    private const int TokenRefreshRetryAttempts = 3;
    private const int DelayBetweenRefreshAttempts = 100; // 100ms

    private readonly IWristbandApiClient mWristbandApiClient;
    private readonly ILoginStateHandler mLoginStateHandler;
    private readonly string mClientId;
    private readonly string mCustomApplicationLoginPageUrl;
    private readonly bool mDangerouslyDisableSecureCookies;
    private readonly bool mIsApplicationCustomDomainActive;
    private readonly string mLoginStateSecret;
    private readonly string mLoginUrl;
    private readonly string mRedirectUri;
    private readonly string mParseTenantFromRootDomain;
    private readonly List<string> mScopes;
    private readonly int mTokenExpirationBuffer;
    private readonly string mWristbandApplicationVanityDomain;

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
        if (string.IsNullOrEmpty(authConfig.ClientId))
        {
            throw new ArgumentException("The [ClientId] config must have a value.");
        }

        if (string.IsNullOrEmpty(authConfig.ClientSecret))
        {
            throw new ArgumentException("The [ClientSecret] config must have a value.");
        }

        if (string.IsNullOrEmpty(authConfig.LoginStateSecret) || authConfig.LoginStateSecret.Length < 32)
        {
            throw new ArgumentException("The [LoginStateSecret] config must have a value of at least 32 characters.");
        }

        if (string.IsNullOrEmpty(authConfig.LoginUrl))
        {
            throw new ArgumentException("The [LoginUrl] config must have a value.");
        }

        if (string.IsNullOrEmpty(authConfig.RedirectUri))
        {
            throw new ArgumentException("The [RedirectUri] config must have a value.");
        }

        if (authConfig.TokenExpirationBuffer.HasValue && authConfig.TokenExpirationBuffer.Value < 0)
        {
            throw new ArgumentException("The [TokenExpirationBuffer] config cannot be negative.");
        }

        if (string.IsNullOrEmpty(authConfig.WristbandApplicationVanityDomain))
        {
            throw new ArgumentException("The [WristbandApplicationVanityDomain] config must have a value.");
        }

        if (!string.IsNullOrEmpty(authConfig.ParseTenantFromRootDomain))
        {
            if (!authConfig.LoginUrl.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [LoginUrl] must contain the \"{TenantDomainToken}\" token when using tenant subdomains.");
            }

            if (!authConfig.RedirectUri.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [RedirectUri] must contain the \"{TenantDomainToken}\" token when using tenant subdomains.");
            }
        }
        else
        {
            if (authConfig.LoginUrl.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [LoginUrl] cannot contain the \"{TenantDomainToken}\" token when tenant subdomains are not used.");
            }

            if (authConfig.RedirectUri.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [RedirectUri] cannot contain the \"{TenantDomainToken}\" token when tenant subdomains are not used.");
            }
        }

        // Create a client using the factory - validation happens inside the factory
        mWristbandApiClient = new WristbandApiClient(authConfig, httpClientFactory);
        mLoginStateHandler = new LoginStateHandler();

        mClientId = authConfig.ClientId;
        mCustomApplicationLoginPageUrl = string.IsNullOrEmpty(authConfig.CustomApplicationLoginPageUrl) ? string.Empty : authConfig.CustomApplicationLoginPageUrl;
        mDangerouslyDisableSecureCookies = authConfig.DangerouslyDisableSecureCookies.HasValue ? authConfig.DangerouslyDisableSecureCookies.Value : false;
        mIsApplicationCustomDomainActive = authConfig.IsApplicationCustomDomainActive.HasValue ? authConfig.IsApplicationCustomDomainActive.Value : false;
        mLoginStateSecret = authConfig.LoginStateSecret;
        mLoginUrl = authConfig.LoginUrl;
        mRedirectUri = authConfig.RedirectUri;
        mParseTenantFromRootDomain = string.IsNullOrEmpty(authConfig.ParseTenantFromRootDomain) ? string.Empty : authConfig.ParseTenantFromRootDomain;
        mScopes = (authConfig.Scopes != null && authConfig.Scopes.Count > 0) ? authConfig.Scopes : new List<string> { "openid", "offline_access", "email" };
        mTokenExpirationBuffer = authConfig.TokenExpirationBuffer ?? DefaultTokenExpirationBuffer;
        mWristbandApplicationVanityDomain = authConfig.WristbandApplicationVanityDomain;
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

        // Determine which domain-related values are present as it will be needed for the authorize URL.
        var tenantCustomDomain = ResolveTenantCustomDomainParam(context);
        var tenantDomainName = ResolveTenantDomainName(context, mParseTenantFromRootDomain);
        var defaultTenantCustomDomain = loginConfig.DefaultTenantCustomDomain ?? string.Empty;
        var defaultTenantDomainName = loginConfig.DefaultTenantDomainName ?? string.Empty;

        // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
        if (string.IsNullOrEmpty(tenantCustomDomain) &&
            string.IsNullOrEmpty(tenantDomainName) &&
            string.IsNullOrEmpty(defaultTenantCustomDomain) &&
            string.IsNullOrEmpty(defaultTenantDomainName))
        {
            var apploginUrl = !string.IsNullOrEmpty(mCustomApplicationLoginPageUrl)
                ? mCustomApplicationLoginPageUrl : $"https://{mWristbandApplicationVanityDomain}/login";
            return await Task.FromResult($"{apploginUrl}?client_id={mClientId}");
        }

        // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
        var customState = loginConfig.CustomState != null && loginConfig.CustomState.Keys.Any()
            ? loginConfig.CustomState
            : null;

        var loginState = mLoginStateHandler.CreateLoginState(context, mRedirectUri, customState);

        mLoginStateHandler.CreateLoginStateCookie(context, loginState, mLoginStateSecret, mDangerouslyDisableSecureCookies);

        // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
        var queryParams = new Dictionary<string, string>
        {
            { "client_id", mClientId },
            { "redirect_uri", mRedirectUri },
            { "response_type", "code" },
            { "state", loginState.State },
            { "scope", string.Join(" ", mScopes) },
            { "code_challenge", CreateCodeChallenge(loginState.CodeVerifier) },
            { "code_challenge_method", "S256" },
            { "nonce", mLoginStateHandler.GenerateRandomString(32) },
            { "login_hint", context.Request.Query["login_hint"].FirstOrDefault() ?? string.Empty },
        };

        var separator = mIsApplicationCustomDomainActive ? '.' : '-';
        var queryString = string.Join("&", queryParams
            .Where(p => p.Value != null)
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));

        // Domain priority order resolution:
        // 1)  tenant_custom_domain query param
        // 2a) tenant subdomain
        // 2b) tenant_domain query param
        // 3)  defaultTenantCustomDomain login config
        // 4)  defaultTenantDomainName login config
        if (!string.IsNullOrEmpty(tenantCustomDomain))
        {
            return await Task.FromResult($"https://{tenantCustomDomain}/api/v1/oauth2/authorize?{queryString}");
        }

        if (!string.IsNullOrEmpty(tenantDomainName))
        {
            return await Task.FromResult($"https://{tenantDomainName}{separator}{mWristbandApplicationVanityDomain}/api/v1/oauth2/authorize?{queryString}");
        }

        if (!string.IsNullOrEmpty(defaultTenantCustomDomain))
        {
            return await Task.FromResult($"https://{defaultTenantCustomDomain}/api/v1/oauth2/authorize?{queryString}");
        }

        return await Task.FromResult($"https://{defaultTenantDomainName}{separator}{mWristbandApplicationVanityDomain}/api/v1/oauth2/authorize?{queryString}");
    }

    /// <summary>
    /// Implements <see cref="IWristbandAuthService.Callback"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<CallbackResult> Callback(HttpContext context)
    {
        context.Response.Headers.Append("Cache-Control", "no-store");
        context.Response.Headers.Append("Pragma", "no-cache");

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

        // Resolve and validate the tenant domain name
        var resolvedTenantDomainName = ResolveTenantDomainName(context, mParseTenantFromRootDomain);
        if (string.IsNullOrEmpty(resolvedTenantDomainName))
        {
            var errorCode = !string.IsNullOrEmpty(mParseTenantFromRootDomain)
                ? "missing_tenant_subdomain"
                : "missing_tenant_domain";
            var errorMessage = !string.IsNullOrEmpty(mParseTenantFromRootDomain)
                ? "Callback request URL is missing a tenant subdomain"
                : "Callback request is missing the [tenant_domain] query parameter from Wristband";
            throw new WristbandError(errorCode, errorMessage);
        }

        // Construct the tenant login URL in the event we have to redirect to the login endpoint
        string tenantLoginUrl;
        if (!string.IsNullOrEmpty(mParseTenantFromRootDomain))
        {
            tenantLoginUrl = mLoginUrl.Replace(TenantDomainToken, resolvedTenantDomainName);
        }
        else
        {
            tenantLoginUrl = $"{mLoginUrl}?tenant_domain={resolvedTenantDomainName}";
        }

        if (!string.IsNullOrEmpty(tenantCustomDomainParam))
        {
            var querySeparator = !string.IsNullOrEmpty(mParseTenantFromRootDomain) ? "?" : "&";
            tenantLoginUrl = $"{tenantLoginUrl}{querySeparator}tenant_custom_domain={tenantCustomDomainParam}";
        }

        // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
        var loginStateCookie = mLoginStateHandler.GetAndClearLoginStateCookie(context, mDangerouslyDisableSecureCookies);
        if (string.IsNullOrEmpty(loginStateCookie))
        {
            return new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, tenantLoginUrl);
        }

        var loginState = mLoginStateHandler.DecryptLoginState(loginStateCookie, mLoginStateSecret);
        if (loginState == null)
        {
            return new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, tenantLoginUrl);
        }

        // Check for any potential error conditions
        if (paramState != loginState.State)
        {
            return new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, tenantLoginUrl);
        }

        if (!string.IsNullOrEmpty(error))
        {
            if (!error.Equals(LoginRequiredError, StringComparison.OrdinalIgnoreCase))
            {
                throw new WristbandError(error, errorDescription);
            }

            return new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, tenantLoginUrl);
        }

        // Exchange the authorization code for tokens
        if (string.IsNullOrEmpty(code))
        {
            throw new ArgumentException("Invalid query parameter [code] passed from Wristband during callback");
        }

        try
        {
            var tokenResponse = await mWristbandApiClient.GetTokens(code, loginState.RedirectUri, loginState.CodeVerifier);
            var userInfo = await mWristbandApiClient.GetUserinfo(tokenResponse.AccessToken);
            var expiresIn = (tokenResponse?.ExpiresIn ?? 0) - mTokenExpirationBuffer;
            var expiresAt = DateTimeOffset.Now.ToUnixTimeMilliseconds() + (expiresIn * 1000);
            var callbackData = new CallbackData(
                tokenResponse?.AccessToken ?? string.Empty,
                expiresAt,
                expiresIn,
                tokenResponse?.IdToken ?? string.Empty,
                tokenResponse?.RefreshToken,
                userInfo,
                resolvedTenantDomainName,
                tenantCustomDomainParam,
                loginState.CustomState,
                loginState.ReturnUrl);
            return new CallbackResult(CallbackResultType.COMPLETED, callbackData, null);
        }
        catch (InvalidGrantError)
        {
            // Handle "invalid_grant" errors gracefully
            return new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, tenantLoginUrl);
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

        if (!string.IsNullOrWhiteSpace(logoutConfig.RefreshToken))
        {
            await mWristbandApiClient.RevokeRefreshToken(logoutConfig.RefreshToken);
        }

        // The client ID is always required by the Wristband Logout Endpoint.
        var tenantDomainName = ResolveTenantDomainName(context, mParseTenantFromRootDomain);
        var tenantCustomDomainParam = ResolveTenantCustomDomainParam(context);
        var redirectUrl = !string.IsNullOrEmpty(logoutConfig.RedirectUrl) ? $"&redirect_url={logoutConfig.RedirectUrl}" : string.Empty;
        var logoutPath = $"/api/v1/logout?client_id={mClientId}{redirectUrl}";
        string separator = mIsApplicationCustomDomainActive ? "." : "-";

        // Domain priority order resolution:
        // 1) If the LogoutConfig has a tenant custom domain explicitly defined, use that.
        if (!string.IsNullOrWhiteSpace(logoutConfig.TenantCustomDomain))
        {
            return $"https://{logoutConfig.TenantCustomDomain}{logoutPath}";
        }

        // 2) If the LogoutConfig has a tenant domain defined, then use that.
        if (!string.IsNullOrWhiteSpace(logoutConfig.TenantDomainName))
        {
            return $"https://{logoutConfig.TenantDomainName}{separator}{mWristbandApplicationVanityDomain}{logoutPath}";
        }

        // 3) If the tenant_custom_domain query param exists, then use that.
        if (!string.IsNullOrEmpty(tenantCustomDomainParam))
        {
            return $"https://{tenantCustomDomainParam}{logoutPath}";
        }

        // 4a) If tenant subdomains are enabled, get the tenant domain from the host.
        // 4b) Otherwise, if tenant subdomains are not enabled, then look for it in the tenant_domain query param.
        if (!string.IsNullOrEmpty(tenantDomainName))
        {
            return $"https://{tenantDomainName}{separator}{mWristbandApplicationVanityDomain}{logoutPath}";
        }

        // Fallback to app login URL (or custom logout redirect URL) if tenant cannot be determined
        var appLoginUrl = !string.IsNullOrEmpty(mCustomApplicationLoginPageUrl)
            ? mCustomApplicationLoginPageUrl
            : $"https://{mWristbandApplicationVanityDomain}/login";
        return !string.IsNullOrEmpty(logoutConfig.RedirectUrl)
                ? logoutConfig.RedirectUrl
                : $"{appLoginUrl}?client_id={mClientId}";
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

        if (expiresAt <= 0)
        {
            throw new ArgumentException("The expiresAt field must be a positive integer");
        }

        if (!IsExpired(expiresAt))
        {
            return null;
        }

        // Make 3 attempts to refresh the token
        for (int attempt = 1; attempt <= TokenRefreshRetryAttempts; attempt++)
        {
            try
            {
                var tokenResponse = await mWristbandApiClient.RefreshToken(refreshToken);
                var newExpiresIn = (tokenResponse?.ExpiresIn ?? 0) - mTokenExpirationBuffer;
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
                var actionString = attempt == TokenRefreshRetryAttempts ? "Aborting..." : "Retrying...";
                Console.WriteLine($"Attempt {attempt} failed. {actionString}");
                Console.WriteLine($"Exception Stack Trace: {ex}");

                // Bail the process on invalid refresh token
                if (ex.Error == "invalid_refresh_token" || attempt == TokenRefreshRetryAttempts)
                {
                    throw;
                }

                await Task.Delay(TokenRefreshRetryAttempts);
            }
            catch (Exception ex)
            {
                var actionString = attempt == TokenRefreshRetryAttempts ? "Aborting..." : "Retrying...";
                Console.WriteLine($"Attempt {attempt} failed. {actionString}");
                Console.WriteLine($"Exception Stack Trace: {ex}");

                if (attempt == TokenRefreshRetryAttempts)
                {
                    throw;
                }

                await Task.Delay(DelayBetweenRefreshAttempts);
            }
        }

        throw new InvalidOperationException("Invalid state reached during refresh token operation.");
    }

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
        if (string.IsNullOrEmpty(host))
        {
            return string.Empty;
        }

        var dotIndex = host.IndexOf('.');
        if (dotIndex < 0)
        {
            return string.Empty;
        }

        var subdomain = host.Substring(0, dotIndex);
        return !string.IsNullOrEmpty(parseTenantFromRootDomain) && host.Substring(dotIndex + 1) == parseTenantFromRootDomain
            ? subdomain
            : string.Empty;
    }

    private static string ResolveTenantDomainName(HttpContext context, string parseTenantFromRootDomain)
    {
        if (!string.IsNullOrEmpty(parseTenantFromRootDomain))
        {
            var host = context.Request.Host.Value ?? string.Empty;
            return ParseTenantSubdomain(host, parseTenantFromRootDomain);
        }

        var tenantDomainParam = context.Request.Query["tenant_domain"].FirstOrDefault();

        if (!string.IsNullOrEmpty(tenantDomainParam) && tenantDomainParam.Contains(","))
        {
            throw new ArgumentException("More than one [tenant_domain] query parameter was encountered");
        }

        // Return the tenant domain if it exists, otherwise return an empty string
        return tenantDomainParam ?? string.Empty;
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
}
