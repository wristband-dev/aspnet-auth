using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

public interface IWristbandAuthService
{
    Task<CallbackResult> Callback(HttpContext context);
    Task<string> Login(HttpContext context, LoginConfig? loginConfig);
    Task<string> Logout(HttpContext context, LogoutConfig logoutConfig);
    Task<TokenData?> RefreshTokenIfExpired(string? refreshToken, long expiresAt = 0);
}

public class WristbandAuthService : IWristbandAuthService
{
    private const string TenantDomainToken = "{tenant_domain}";
    private const string LoginStateCookiePrefix = "login";
    private const int MaxNumberOfLoginStateCookies = 3;
    private const string LoginRequiredError = "login_required";
    private const int TokenRefreshRetryAttempts = 3;
    private const int DelayBetweenRefreshAttempts = 100; // 100ms

    private readonly WristbandNetworking mWristbandNetworking;
    private readonly string mClientId;
    private readonly string mCustomApplicationLoginPageUrl;
    private readonly bool mDangerouslyDisableSecureCookies;
    private readonly string mLoginStateSecret;
    private readonly string mLoginUrl;
    private readonly string mRedirectUri;
    private readonly string mRootDomain;
    private readonly List<string> mScopes;
    private readonly bool mUseCustomDomains;
    private readonly bool mUseTenantSubdomains;
    private readonly string mWristbandApplicationDomain;

    public WristbandAuthService(AuthConfig authConfig)
    {
        if (string.IsNullOrEmpty(authConfig.ClientId))
        {
            throw new ArgumentException("The [clientId] config must have a value.");
        }

        if (string.IsNullOrEmpty(authConfig.ClientSecret))
        {
            throw new ArgumentException("The [clientSecret] config must have a value.");
        }

        if (string.IsNullOrEmpty(authConfig.LoginStateSecret) || authConfig.LoginStateSecret.Length < 32)
        {
            throw new ArgumentException("The [loginStateSecret] config must have a value of at least 32 characters.");
        }

        if (string.IsNullOrEmpty(authConfig.LoginUrl))
        {
            throw new ArgumentException("The [loginUrl] config must have a value.");
        }

        if (string.IsNullOrEmpty(authConfig.RedirectUri))
        {
            throw new ArgumentException("The [redirectUri] config must have a value.");
        }

        if (string.IsNullOrEmpty(authConfig.WristbandApplicationDomain))
        {
            throw new ArgumentException("The [wristbandApplicationDomain] config must have a value.");
        }

        if (authConfig.UseTenantSubdomains.HasValue && authConfig.UseTenantSubdomains.Value)
        {
            if (string.IsNullOrEmpty(authConfig.RootDomain))
            {
                throw new ArgumentException("The [rootDomain] config must have a value when using tenant subdomains.");
            }

            if (!authConfig.LoginUrl.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [loginUrl] must contain the \"{TenantDomainToken}\" token when using tenant subdomains.");
            }

            if (!authConfig.RedirectUri.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [redirectUri] must contain the \"{TenantDomainToken}\" token when using tenant subdomains.");
            }
        }
        else
        {
            if (authConfig.LoginUrl.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [loginUrl] cannot contain the \"{TenantDomainToken}\" token when tenant subdomains are not used.");
            }

            if (authConfig.RedirectUri.Contains(TenantDomainToken))
            {
                throw new ArgumentException($"The [redirectUri] cannot contain the \"{TenantDomainToken}\" token when tenant subdomains are not used.");
            }
        }

        mWristbandNetworking = new WristbandNetworking(authConfig);

        mClientId = authConfig.ClientId;
        mCustomApplicationLoginPageUrl = string.IsNullOrEmpty(authConfig.CustomApplicationLoginPageUrl) ? string.Empty : authConfig.CustomApplicationLoginPageUrl;
        mDangerouslyDisableSecureCookies = authConfig.DangerouslyDisableSecureCookies.HasValue ? authConfig.DangerouslyDisableSecureCookies.Value : false;
        mLoginStateSecret = authConfig.LoginStateSecret;
        mLoginUrl = authConfig.LoginUrl;
        mRedirectUri = authConfig.RedirectUri;
        mRootDomain = string.IsNullOrEmpty(authConfig.RootDomain) ? string.Empty : authConfig.RootDomain;
        mScopes = (authConfig.Scopes != null && authConfig.Scopes.Count > 0) ? authConfig.Scopes : new List<string> { "openid", "offline_access", "email" };
        mUseCustomDomains = authConfig.UseCustomDomains.HasValue ? authConfig.UseCustomDomains.Value : false;
        mUseTenantSubdomains = authConfig.UseTenantSubdomains.HasValue ? authConfig.UseTenantSubdomains.Value : false;
        mWristbandApplicationDomain = authConfig.WristbandApplicationDomain;
    }

    // ////////////////////////////////////
    //   LOGIN
    // ////////////////////////////////////

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
        var tenantDomainName = ResolveTenantDomainName(context, mUseTenantSubdomains, mRootDomain);
        var defaultTenantCustomDomain = loginConfig.DefaultTenantCustomDomain ?? string.Empty;
        var defaultTenantDomainName = loginConfig.DefaultTenantDomainName ?? string.Empty;

        // In the event we cannot determine either a tenant custom domain or subdomain, send the user to app-level login.
        if (string.IsNullOrEmpty(tenantCustomDomain) &&
            string.IsNullOrEmpty(tenantDomainName) &&
            string.IsNullOrEmpty(defaultTenantCustomDomain) &&
            string.IsNullOrEmpty(defaultTenantDomainName))
        {
            var apploginUrl = mCustomApplicationLoginPageUrl ?? $"https://{mWristbandApplicationDomain}/login";
            return await Task.FromResult($"{apploginUrl}?client_id={mClientId}");
        }

        // Create the login state which will be cached in a cookie so that it can be accessed in the callback.
        var customState = loginConfig.CustomState != null && loginConfig.CustomState.Keys.Any()
            ? loginConfig.CustomState
            : null;
        var loginState = CreateLoginState(context, mRedirectUri, customState);

        // Clear any stale login state cookies and add a new one fo rthe current request.
        ClearOldestLoginStateCookies(context);
        var encryptedLoginState = EncryptLoginState(loginState, mLoginStateSecret);
        CreateLoginStateCookie(context, loginState.State, encryptedLoginState, mDangerouslyDisableSecureCookies);

        // Create the Wristband Authorize Endpoint URL which the user will get redirectd to.
        var queryParams = new Dictionary<string, string>
        {
            {"client_id", mClientId},
            {"redirect_uri", mRedirectUri},
            {"response_type", "code"},
            {"state", loginState.State},
            {"scope", string.Join(" ", mScopes)},
            {"code_challenge", CreateCodeChallenge(loginState.CodeVerifier)},
            {"code_challenge_method", "S256"},
            {"nonce", GenerateRandomString(32)},
            {"login_hint", context.Request.Query["login_hint"].FirstOrDefault() ?? string.Empty },
        };

        var separator = mUseCustomDomains ? '.' : '-';
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
            return await Task.FromResult($"https://{tenantDomainName}{separator}{mWristbandApplicationDomain}/api/v1/oauth2/authorize?{queryString}");
        }
        if (!string.IsNullOrEmpty(defaultTenantCustomDomain))
        {
            return await Task.FromResult($"https://{defaultTenantCustomDomain}/api/v1/oauth2/authorize?{queryString}");
        }

        return await Task.FromResult($"https://{defaultTenantDomainName}{separator}{mWristbandApplicationDomain}/api/v1/oauth2/authorize?{queryString}");
    }

    // ////////////////////////////////////
    //   CALLBACK
    // ////////////////////////////////////
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
        var resolvedTenantDomainName = ResolveTenantDomainName(context, mUseTenantSubdomains, mRootDomain);
        if (string.IsNullOrEmpty(resolvedTenantDomainName))
        {
            var errorCode = mUseTenantSubdomains ? "missing_tenant_subdomain" : "missing_tenant_domain";
            var errorMessage = mUseTenantSubdomains
                ? "Callback request URL is missing a tenant subdomain"
                : "Callback request is missing the [tenant_domain] query parameter from Wristband";
            throw new WristbandError(errorCode, errorMessage);
        }

        // Construct the tenant login URL in the event we have to redirect to the login endpoint
        string tenantLoginUrl;
        if (mUseTenantSubdomains)
        {
            tenantLoginUrl = mLoginUrl.Replace(TenantDomainToken, resolvedTenantDomainName);
        }
        else
        {
            tenantLoginUrl = $"{mLoginUrl}?tenant_domain={resolvedTenantDomainName}";
        }

        if (!string.IsNullOrEmpty(tenantCustomDomainParam))
        {
            var querySeparator = mUseTenantSubdomains ? "?" : "&";
            tenantLoginUrl = $"{tenantLoginUrl}{querySeparator}tenant_custom_domain={tenantCustomDomainParam}";
        }

        // Make sure the login state cookie exists, extract it, and set it to be cleared by the server.
        var loginStateCookie = GetAndClearLoginStateCookie(context);
        if (string.IsNullOrEmpty(loginStateCookie))
        {
            return new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, tenantLoginUrl);
        }

        var loginState = DecryptLoginState(loginStateCookie, mLoginStateSecret);
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
            var tokenResponse = await mWristbandNetworking.GetTokens(code, loginState.RedirectUri, loginState.CodeVerifier);
            var userInfo = await mWristbandNetworking.GetUserinfo(tokenResponse.AccessToken);
            var callbackData = new CallbackData(
                tokenResponse?.AccessToken ?? string.Empty,
                tokenResponse?.ExpiresIn ?? 0,
                tokenResponse?.IdToken ?? string.Empty,
                tokenResponse?.RefreshToken,
                userInfo,
                resolvedTenantDomainName,
                tenantCustomDomainParam,
                loginState.CustomState,
                loginState.ReturnUrl
            );
            return new CallbackResult(CallbackResultType.COMPLETED, callbackData, null);
        }
        catch (WristbandError ex)
        {
            // Handle "invalid_grant" errors gracefully
            Console.WriteLine($"Callback error [{ex.Error}] from Token response: {ex.ErrorDescription}");
            return new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, tenantLoginUrl);
        }
    }

    // ////////////////////////////////////
    //   LOGOUT
    // ////////////////////////////////////
    public async Task<string> Logout(HttpContext context, LogoutConfig? logoutConfig)
    {
        context.Response.Headers.Append("Cache-Control", "no-store");
        context.Response.Headers.Append("Pragma", "no-cache");

        if (logoutConfig == null)
        {
            logoutConfig = new LogoutConfig();
        }

        if (!string.IsNullOrEmpty(logoutConfig.RefreshToken))
        {
            await mWristbandNetworking.RevokeRefreshToken(logoutConfig.RefreshToken);
        }

        // The client ID is always required by the Wristband Logout Endpoint.
        var redirectUrl = !string.IsNullOrEmpty(logoutConfig.RedirectUrl) ? $"&redirect_url={logoutConfig.RedirectUrl}" : "";
        var logoutQuery = $"client_id={mClientId}{redirectUrl}";

        // Construct the appropriate Logout Endpoint URL that the user will get redirected to.
        var host = context.Request.Host.Value;
        var appLoginUrl = !string.IsNullOrEmpty(mCustomApplicationLoginPageUrl)
            ? mCustomApplicationLoginPageUrl
            : $"https://{mWristbandApplicationDomain}/login";

        if (string.IsNullOrEmpty(logoutConfig.TenantCustomDomain))
        {
            if (mUseTenantSubdomains &&
                host != null &&
                host.Substring(host.IndexOf('.') + 1) != mRootDomain)
            {
                return !string.IsNullOrEmpty(logoutConfig.RedirectUrl)
                    ? logoutConfig.RedirectUrl
                    : $"{appLoginUrl}?client_id={mClientId}";
            }

            if (!mUseTenantSubdomains && string.IsNullOrEmpty(logoutConfig.TenantDomainName))
            {
                return !string.IsNullOrEmpty(logoutConfig.RedirectUrl)
                    ? logoutConfig.RedirectUrl
                    : $"{appLoginUrl}?client_id={mClientId}";
            }
        }

        string tenantDomainName = mUseTenantSubdomains && host != null && host.Contains(".")
            ? host.Substring(0, host.IndexOf('.'))
            : logoutConfig.TenantDomainName ?? string.Empty;
        string separator = mUseCustomDomains ? "." : "-";
        string tenantDomainToUse = !string.IsNullOrEmpty(logoutConfig.TenantCustomDomain)
            ? logoutConfig.TenantCustomDomain
            : $"{tenantDomainName}{separator}{mWristbandApplicationDomain}";

        return $"https://{tenantDomainToUse}/api/v1/logout?{logoutQuery}";
    }

    // ////////////////////////////////////
    //   REFRESH TOKEN IF EXPIRED
    // ////////////////////////////////////
    public async Task<TokenData?> RefreshTokenIfExpired(string? refreshToken, long expiresAt = 0)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            throw new ArgumentException("Refresh token must be a valid string");
        }

        if (expiresAt <= 0)
        {
            throw new ArgumentException("The expiresAt field must be a positive integer");
        }

        if (IsExpired(expiresAt))
        {
            return null;
        }

        // Make 3 attempts to refresh the token
        for (int attempt = 1; attempt <= TokenRefreshRetryAttempts; attempt++)
        {
            try
            {
                var tokenResponse = await mWristbandNetworking.RefreshToken(refreshToken);
                return tokenResponse;
            }
            catch (WristbandError ex)
            {
                var actionString = attempt == TokenRefreshRetryAttempts ? "Aborting..." : "Retrying...";
                Console.WriteLine($"Attempt {attempt} failed. {actionString}");
                Console.WriteLine($"Exception Stack Trace: {ex.ToString()}");

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
                Console.WriteLine($"Exception Stack Trace: {ex.ToString()}");

                if (attempt == TokenRefreshRetryAttempts)
                {
                    throw;
                }

                await Task.Delay(DelayBetweenRefreshAttempts);
            }
        }

        throw new InvalidOperationException("Invalid state reached during refresh token operation.");
    }

    // ////////////////////////////////////////////////////////////
    //   PRIVATE METHODS
    // ////////////////////////////////////////////////////////////

    private static void ClearOldestLoginStateCookies(HttpContext context)
    {
        // A login cookie is used to store the challenge code while the login process
        // is happening. Once the login process is complete, the cookie is no longer needed.
        var cookies = context.Request.Cookies;
        var orderedLoginCookies = cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}#"))
            .OrderBy(c =>
            {
                // Attempt to parse the index part of the key; handle parsing failure.
                var parts = c.Key.Split('#');
                return parts.Length > 2 && long.TryParse(parts[2], out var result) ? result : long.MaxValue;
            })
            .ToList();

        if (orderedLoginCookies.Count < MaxNumberOfLoginStateCookies)
        {
            return;
        }

        // Delete the oldest login state cookies until we are back under the limit
        var numberOfCookiesToDelete = orderedLoginCookies.Count - MaxNumberOfLoginStateCookies + 1;
        for (var i = 0; i < numberOfCookiesToDelete; i++)
        {
            context.Response.Cookies.Delete(orderedLoginCookies[i].Key);
        }
    }

    private static LoginState CreateLoginState(HttpContext context, string redirectUri, Dictionary<string, object>? customState)
    {
        var returnUrl = string.Empty;

        if (context.Request.Query.TryGetValue("return_url", out var returnUrlValue))
        {
            if (returnUrlValue.Count > 1)
            {
                throw new ArgumentException("More than one [return_url] query parameter was encountered.");
            }

            returnUrl = returnUrlValue.ToString();
        }

        if (returnUrl.Contains(" "))
        {
            throw new ArgumentException("Return URL should not contain spaces.");
        }

        var loginState = new LoginState(
            GenerateRandomString(32),
            GenerateRandomString(32),
            redirectUri,
            returnUrl,
            customState
        );

        return loginState;
    }

    private void CreateLoginStateCookie(HttpContext context, string state, string encryptedLoginState, bool dangerouslyDisableSecureCookies)
    {
        // Add the new login state cookie (1 hour max age).
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            MaxAge = TimeSpan.FromHours(1),
            Path = "/",
            SameSite = SameSiteMode.Lax,
            Secure = !dangerouslyDisableSecureCookies
        };
        var cookieName = $"{LoginStateCookiePrefix}#{state}#{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        context.Response.Cookies.Append(cookieName, encryptedLoginState, cookieOptions);
    }

    private static string CreateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        var base64 = Convert.ToBase64String(challengeBytes);
        return base64.Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }

    private LoginState DecryptLoginState(string encryptedState, string loginStateSecret)
    {
        var parts = encryptedState.Split(new[] { '|' }, 2);
        var encrypted = Convert.FromBase64String(parts[0]);
        var iv = Convert.FromBase64String(parts[1]);

        var key = Convert.FromBase64String(loginStateSecret);
        if (key.Length != 32)
        {
            throw new ArgumentException("Invalid key size. Must be 32 bytes for AES-256.");
        }

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);

        try
        {
            var loginState = JsonSerializer.Deserialize<LoginState>(Encoding.UTF8.GetString(decrypted));
            if (loginState == null)
            {
                throw new InvalidOperationException("Failed to deserialize JSON for LoginState.");
            }

            return loginState;
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Invalid JSON format for LoginState.", ex);
        }
    }

    //
    // NOTE: Create LoginStateSecret via `openssl rand -base64 32`
    //
    private string EncryptLoginState(LoginState loginState, string loginStateSecret)
    {
        var key = Convert.FromBase64String(loginStateSecret);
        if (key.Length != 32)
        {
            throw new ArgumentException("Invalid key size. Must be 32 bytes for AES-256.");
        }
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        var plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(loginState));
        var encrypted = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        return Convert.ToBase64String(encrypted) + "|" + Convert.ToBase64String(aes.IV);
    }

    private static string GenerateRandomString(int length)
    {
        using var rng = RandomNumberGenerator.Create();
        var randomBytes = new byte[length];
        rng.GetBytes(randomBytes);
        var base64 = Convert.ToBase64String(randomBytes);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static string GetAndClearLoginStateCookie(HttpContext context)
    {
        //
        // A login cookie is used to store the challenge code while the login process
        // is happening. Once the login process is complete, the cookie is no longer needed.
        //
        var state = context.Request.Query["state"].FirstOrDefault() ?? string.Empty;

        // This should resolve to a single cookie with this prefix or no cookie at all if it got cleared or expired.
        var matchingLoginStateCookies = context.Request.Cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}#{state}#"))
            .OrderBy(c => long.Parse(c.Key?.Split('#')[2] ?? string.Empty))
            .ToList();

        var allLoginStateCookies = context.Request.Cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}#"))
            .ToList();

        var loginStateCookie = "";

        if (matchingLoginStateCookies.Count > 0)
        {
            loginStateCookie = matchingLoginStateCookies.Last().Value; // use the newest cookie matching the state
        }

        foreach (var cookie in allLoginStateCookies)
        {
            context.Response.Cookies.Delete(cookie.Key);
        }

        return loginStateCookie;
    }

    private static bool IsExpired(long expiresAt)
    {
        var currentTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        return currentTime >= expiresAt;
    }

    private static string ParseTenantSubdomain(string host, string rootDomain)
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
        return host.Substring(dotIndex + 1) == rootDomain ? subdomain : string.Empty;
    }

    private static string ResolveTenantDomainName(HttpContext context, bool useTenantSubdomains, string rootDomain)
    {
        if (useTenantSubdomains)
        {
            var host = context.Request.Host.Value;
            return ParseTenantSubdomain(host, rootDomain);
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
