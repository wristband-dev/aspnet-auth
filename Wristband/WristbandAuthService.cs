using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

namespace Wristband;

public interface IWristbandAuthService
{
    Task<string?> Callback(HttpContext context);
    Task<string> Login(HttpContext context);
    string LoginCompleted(HttpContext context);
    Task<string> Logout(HttpContext context);
    Task<TokenData?> RefreshTokenIfExpired(string? refreshToken, long? expiresAt);
}

public class WristbandAuthService : IWristbandAuthService
{
    private const string LoginStateCookiePrefix = "login";
    private readonly WristbandNetworking mWristbandNetworking;
    private readonly AuthConfig mAuthConfig;
    private readonly LoginConfig mLoginConfig;
    private readonly LogoutConfig mLogoutConfig;

    public WristbandAuthService(
        IHttpClientFactory httpClientFactory,
        AuthConfig authConfig,
        LoginConfig loginConfig,
        LogoutConfig logoutConfig)
    {
        mAuthConfig = authConfig;
        mLoginConfig = loginConfig;
        mLogoutConfig = logoutConfig;
        mWristbandNetworking = new WristbandNetworking(httpClientFactory, authConfig);
    }

    public async Task<string?> Callback(HttpContext context)
    {
        context.Response.Headers.Append("Cache-Control", "no-store");
        context.Response.Headers.Append("Pragma", "no-cache");

        var query = context.Request.Query;
        if (query == null)
        {
            throw new WristbandError("invalid_request", "Missing query string");
        }
        var code = query["code"].ToString();
        var state = query["state"].ToString();
        var error = query["error"].ToString();
        var errorDescription = query["error_description"].ToString();

        var tenantSubdomain = ResolveTenantDomain(context, mLoginConfig.DefaultTenantDomain);
        var tenantLoginUrl = mAuthConfig.LoginUrl.Replace("{tenant_domain}", tenantSubdomain);

        var loginStateCookie = GetAndClearLoginStateCookie(context);
        if (string.IsNullOrEmpty(loginStateCookie) )
        {
            return tenantLoginUrl;
        }

        var loginState = DecryptLoginState(loginStateCookie);
        if (loginState == null || loginState.State != state)
        {

            return tenantLoginUrl;
        }

        if (!string.IsNullOrEmpty(error))
        {
            if (!error.Equals("login_required", StringComparison.OrdinalIgnoreCase))
            {
                throw new WristbandError(error, errorDescription);
            }

            return tenantLoginUrl;
        }

        // NOTE: do NOT replace {tenant_url} in the auth/config redirectUri - wristband will do that for us
        var tenantRedirectUri = mAuthConfig.RedirectUri;
        var tokenResponse = await mWristbandNetworking.GetTokens(code, tenantRedirectUri, loginState.CodeVerifier);
        var userinfo = await mWristbandNetworking.GetUserinfo(tokenResponse?.AccessToken ?? string.Empty);

        if (userinfo == null)
        {
            return tenantLoginUrl;
        }

        var userId = "unknown";
        if (userinfo.TryGetValue("sub", out var userIdObj))
        {
            userId = userIdObj.ToString() ?? "unknown";
        }

        var email = "unknown";
        if (userinfo.TryGetValue("email", out var emailObj))
        {
            email = emailObj.ToString() ?? "unknown";
        }

        var name = "unknown";
        if (userinfo.TryGetValue("name", out var nameObj))
        {
            name = nameObj.ToString() ?? "unknown";
        }

        var idp = "wristband";
        if (userinfo.TryGetValue("idp_name", out var idpObj))
        {
            idp = idpObj.ToString() ?? "unknown";
        }

        var roles = new List<WristbandRole>();
        if (userinfo.TryGetValue("roles", out var rolesObj))
        {
            var jsonElement = rolesObj is JsonElement obj ? obj : default;
            if (jsonElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in jsonElement.EnumerateArray())
                {
                    var role = JsonSerializer.Deserialize<WristbandRole>(element.GetRawText());
                    if (role != null)
                    {
                        roles.Add(role);
                    }
                }
            }
        }

        var claims = new List<Claim>()
        {
            new (ClaimTypes.Email, email),
            new (ClaimTypes.Name, name),
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role.Name));
        }

        var claimsIdentity = new ClaimsIdentity(
            claims, CookieAuthenticationDefaults.AuthenticationScheme);

        var authProperties = new AuthenticationProperties
        {
            //AllowRefresh = <bool>,
            // Refreshing the authentication session should be allowed.

            //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
            // The time at which the authentication ticket expires. A
            // value set here overrides the ExpireTimeSpan option of
            // CookieAuthenticationOptions set with AddCookie.

            //IsPersistent = true,
            // Whether the authentication session is persisted across
            // multiple requests. When used with cookies, controls
            // whether the cookie's lifetime is absolute (matching the
            // lifetime of the authentication ticket) or session-based.

            //IssuedUtc = <DateTimeOffset>,
            // The time at which the authentication ticket was issued.

            //RedirectUri = <string>
            // The full path or absolute URI to be used as an http
            // redirect response value.
        };

        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        var callbackData = new CallbackData
        {
            AccessToken = tokenResponse?.AccessToken ?? string.Empty,
            IdToken = tokenResponse?.IdToken ?? string.Empty,
            RefreshToken = tokenResponse?.RefreshToken ?? string.Empty,
            ExpiresIn = tokenResponse?.ExpiresIn ?? 0,
            Userinfo = userinfo,
        };

        SetWristbandSessionKeys(context, callbackData, roles);


        return null;
    }

    public async Task<string> Login(HttpContext context)
    {
        var response = context.Response;
        response.Headers.Append("Cache-Control", "no-store");
        response.Headers.Append("Pragma", "no-cache");

        //
        // Remove any prior authentication state
        //
        await RemoveWristbandSessionKeys(context);

        //
        // TODO Get return_url from query string
        // TODO Store return_url somewhere for use after successful login
        //

        var customState =
            (Dictionary<string, object>?)null; // TODO: Add custom state recorder here

        var tenantDomainName = ResolveTenantDomain(context, mLoginConfig.DefaultTenantDomain);
        // NOTE: do NOT replace {tenant_url} in the auth/config redirectUri - wristband will do that for us
        var tenantRedirectUri = mAuthConfig.RedirectUri;
        var tenantWristbandTenantDomain =
            mAuthConfig.WristbandTenantDomain.Replace("{tenant_domain}", tenantDomainName);

        var loginState = CreateLoginState(context, tenantRedirectUri, new LoginStateMapConfig
        {
            TenantDomainName = tenantDomainName,
            CustomState = customState,
        });

        ClearOldestLoginStateCookies(context);
        var encryptedLoginState = EncryptLoginState(loginState);
        CreateLoginStateCookie(context, loginState.State, encryptedLoginState);

        string loginHint = context.Request.Query["login_hint"];

        var queryParams = new Dictionary<string, string?>
        {
            {"client_id", mAuthConfig.ClientId},
            {"redirect_uri", tenantRedirectUri},
            {"login_hint", loginHint },
            {"response_mode", "query"},
            {"response_type", "code"},
            {"scope", string.Join(" ", mAuthConfig.Scopes)},
            {"state", loginState.State},
            {"code_challenge", CreateCodeChallenge(loginState.CodeVerifier)},
            {"code_challenge_method", "S256"},
        };

        var baseUrl = $"https://{tenantWristbandTenantDomain}/api/v1/oauth2/authorize";
        var authorizeUrl =  QueryHelpers.AddQueryString(baseUrl, queryParams);
        return authorizeUrl;
    }

    public string LoginCompleted(HttpContext context)
    {
        var tenantSubdomain = ResolveTenantDomain(context, mLoginConfig.DefaultTenantDomain);
        //
        // TODO apply return_url stored previously from query string
        //
        var tenantPostLoginRedirectUrl = mLoginConfig.PostLoginRedirectUrl.Replace("{tenant_domain}", tenantSubdomain);
        return tenantPostLoginRedirectUrl;
    }

    public async Task<string> Logout(HttpContext context)
    {
        context.Response.Headers.Append("Cache-Control", "no-store");
        context.Response.Headers.Append("Pragma", "no-cache");

        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        var refreshToken = GetRefreshToken(context);
        await RemoveWristbandSessionKeys(context);

        if (!string.IsNullOrEmpty(refreshToken))
        {
            await mWristbandNetworking.RevokeRefreshToken(refreshToken);
        }

        var tenantSubdomain = ResolveTenantDomain(context, mLoginConfig.DefaultTenantDomain);
        var tenantRedirectUrl = HttpUtility.UrlEncode(mLogoutConfig.RedirectUrl);//.Replace("{tenant_domain}", tenantSubdomain);
        var redirectUrl = !string.IsNullOrEmpty(tenantRedirectUrl) ? $"&redirect_url={tenantRedirectUrl}" : "";
        var logoutQuery = $"client_id={mAuthConfig.ClientId}{redirectUrl}";
        var tenantWristbandTenantDomain = mAuthConfig.WristbandTenantDomain.Replace("{tenant_domain}", tenantSubdomain);
        var logoutUrl = $"https://{tenantWristbandTenantDomain}/api/v1/logout?{logoutQuery}";

        return logoutUrl;
    }

    public async Task<TokenData?> RefreshTokenIfExpired(string? refreshToken, long? expiresAt)
    {
        if (expiresAt == null || expiresAt.Value <= 0)
        {
            throw new ArgumentException("The expiresAt field must be a positive integer");
        }

        if (string.IsNullOrEmpty(refreshToken))
        {
            throw new ArgumentException("Refresh token must be a valid string");
        }

        if (!IsExpired(expiresAt.Value))
        {
            return null;
        }

        var tokenResponse = await mWristbandNetworking.RefreshToken(refreshToken);
        return tokenResponse;
    }

    private static void ClearOldestLoginStateCookies(HttpContext context)
    {
        //
        // A login cookie is used to store the challenge code while the login process
        // is happening. Once the login process is complete, the cookie is no longer needed.
        //
        var cookies = context.Request.Cookies;
        var orderedLoginCookies = cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}."))
            .OrderBy(c => long.Parse(c.Key.Split('.')[2] ?? string.Empty))
            .ToList();

        if (orderedLoginCookies.Count <= 1)
        {
            return;
        }

        // delete the oldest login state cookies, leaving the newest cookie
        for (var i = 0; i < orderedLoginCookies.Count - 1; i++)
        {
            context.Response.Cookies.Delete(orderedLoginCookies[i].Key);
        }
    }

    private static LoginState CreateLoginState(HttpContext context, string tenantRedirectUri, LoginStateMapConfig config)
    {
        var containsKey = context.Request.Query.ContainsKey("return_url");
        var returnUrl = containsKey ? context.Request.Query["return_url"].ToString() : string.Empty;

        if (returnUrl.Contains(" "))
        {
            throw new ArgumentException("Return URL should not contain spaces.");
        }

        var state = GenerateRandomString(32);
        var codeVerifier = GenerateRandomString(32);

        var loginState = new LoginState
        {
            State = state,
            CodeVerifier = codeVerifier,
            RedirectUri = tenantRedirectUri,
            TenantDomainName = config.TenantDomainName,
            CustomState = config.CustomState,
            ReturnUrl = returnUrl,
        };

        return loginState;
    }

    private void CreateLoginStateCookie(HttpContext context, string state, string encryptedLoginState)
    {
        // Add the new login state cookie (1 hour max age is plenty of time for login to complete even when debugging)
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            MaxAge = TimeSpan.FromHours(1),
            Path = "/",
            SameSite = SameSiteMode.Lax,
            Secure = !mAuthConfig.DangerouslyDisableSecureCookies
        };
        var cookieName = $"{LoginStateCookiePrefix}.{state}.{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        context.Response.Cookies.Append(cookieName, encryptedLoginState, cookieOptions);
    }

    private static string CreateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        return WebEncoders.Base64UrlEncode(challengeBytes);
    }

    private LoginState? DecryptLoginState(string? encryptedState)
    {
        try
        {
            if (string.IsNullOrEmpty(encryptedState))
            {
                return null;
            }

            var parts = encryptedState.Split(['|'], 2);
            var encrypted = Convert.FromBase64String(parts[0]);
            var iv = Convert.FromBase64String(parts[1]);
            //
            // NOTE: Create LoginStateSecret via `openssl rand -base64 32`
            //
            var key = Convert.FromBase64String(mAuthConfig.LoginStateSecret);
            if (key.Length != 32)
            {
                throw new ArgumentException("Invalid key size. Must be 32 bytes for AES-256.");
            }
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
            return JsonSerializer.Deserialize<LoginState>(Encoding.UTF8.GetString(decrypted));
        }
        catch
        {
            return null;
        }
    }

    private string EncryptLoginState(LoginState loginState)
    {
        //
        // NOTE: Create LoginStateSecret via `openssl rand -base64 32`
        //
        var key = Convert.FromBase64String(mAuthConfig.LoginStateSecret);
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
        return WebEncoders.Base64UrlEncode(randomBytes);
    }

    private static string GetAndClearLoginStateCookie(HttpContext context)
    {
        //
        // A login cookie is used to store the challenge code while the login process
        // is happening. Once the login process is complete, the cookie is no longer needed.
        //
        var state = context.Request.Query["state"].ToString();

        // This should resolve to a single cookie with this prefix or no cookie at all if it got cleared or expired.
        var matchingLoginStateCookies = context.Request.Cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}.{state}."))
            .OrderBy(c => long.Parse(c.Key?.Split('.')[2] ?? string.Empty))
            .ToList();

        var allLoginStateCookies = context.Request.Cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}."))
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

    private string ResolveTenantDomain(HttpContext context, string defaultTenantDomain)
    {
        if (mAuthConfig.UseTenantSubdomains)
        {
            var host = context.Request.Host.Host;

            var firstDotIndex = host.IndexOf('.');
            var domainPart = host[(firstDotIndex + 1)..];
            if (firstDotIndex > 0 && domainPart.Equals(mAuthConfig.RootDomain, StringComparison.OrdinalIgnoreCase))
            {
                var foundTenantDomain = host[..firstDotIndex];
                return foundTenantDomain;
            }

            return defaultTenantDomain;
        }

        if (context.Request.Query.TryGetValue("tenant_domain", out var tenantDomain))
        {
            return tenantDomain.ToString();
        }

        return defaultTenantDomain;
    }

    public static async Task SetWristbandSessionKeys(
        HttpContext context,
        CallbackData callbackData,
        List<WristbandRole> roles)
    {
        // Set elsewhere intentionally httpContext.Session.SetString("wristband:wristbandAuth", "true");
        context.Session.SetString("wristband:isAuthenticated", string.IsNullOrEmpty(callbackData.AccessToken) ? "false" : "true");
        context.Session.SetString("wristband:accessToken", callbackData.AccessToken);
        context.Session.SetString("wristband:refreshToken", callbackData.RefreshToken);
        context.Session.SetString("wristband:expiresAt",
            $"{DateTimeOffset.Now.ToUnixTimeMilliseconds() + (callbackData.ExpiresIn * 1000)}");
        context.Session.SetString("wristband:idToken", callbackData.IdToken);
        context.Session.SetString("wristband:roles", JsonSerializer.Serialize(roles));

        await context.Session.CommitAsync();
    }
    public static async Task RefreshWristbandSessionKeys(HttpContext context, TokenData tokenData)
    {
        context.Session.SetString("wristband:isAuthenticated", string.IsNullOrEmpty(tokenData.AccessToken) ? "false" : "true");
        context.Session.SetString("wristband:accessToken", tokenData.AccessToken);
        context.Session.SetString("wristband:refreshToken", tokenData.RefreshToken);
        context.Session.SetInt32("wristband:expiresAt", (int)DateTimeOffset.Now.ToUnixTimeMilliseconds() + tokenData.ExpiresIn * 1000);
        if (string.IsNullOrEmpty(tokenData.IdToken) == false)
        {
            context.Session.SetString("wristband:idToken", tokenData.IdToken);
        }

        await context.Session.CommitAsync();
    }
    public static async Task RemoveWristbandSessionKeys(HttpContext context)
    {
        context.Session.Remove("wristband:WristbandAuth");
        context.Session.Remove("wristband:isAuthenticated");
        context.Session.Remove("wristband:accessToken");
        context.Session.Remove("wristband:refreshToken");
        context.Session.Remove("wristband:expiresAt");
        context.Session.Remove("wristband:idToken");
        context.Session.Remove("wristband:roles");

        await context.Session.CommitAsync();
    }

    public static bool GetIsAuthenticated(HttpContext context)
    {
        return context.Session.GetString("wristband:isAuthenticated") == "true";
    }

    public static string GetRefreshToken(HttpContext context)
    {
        return context.Session.GetString("wristband:refreshToken") ?? string.Empty;
    }

    public static long GetExpiresAt(HttpContext context)
    {
        return Int64.Parse(context.Session.GetString("wristband:expiresAt") ?? "0");
    }

    public static List<WristbandRole> GetRoles(HttpContext context)
    {
        var roles = context.Session.GetString("wristband:roles");
        return JsonSerializer.Deserialize<List<WristbandRole>>(roles ?? "[]")!;
    }
}
