using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <inheritdoc cref="ILoginStateHandler" />
internal class LoginStateHandler : ILoginStateHandler
{
    private const string LoginStateCookiePrefix = "login";
    private const string LoginStateCookieSeparator = "#";
    private const int MaxNumberOfLoginStateCookies = 3;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginStateHandler"/> class.
    /// </summary>
    public LoginStateHandler()
    {
    }

    /// <summary>
    /// Implements <see cref="ILoginStateHandler.CreateLoginState"/>.
    /// </summary>
    /// <inheritdoc />
    public LoginState CreateLoginState(HttpContext httpContext, string redirectUri, Dictionary<string, object>? customState)
    {
        var returnUrl = string.Empty;

        if (httpContext.Request.Query.TryGetValue("return_url", out var returnUrlValue))
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

        return new LoginState(
            GenerateRandomString(32),
            GenerateRandomString(32),
            redirectUri,
            returnUrl,
            customState);
    }

    /// <summary>
    /// Implements <see cref="ILoginStateHandler.CreateLoginStateCookie"/>.
    /// </summary>
    /// <inheritdoc />
    public void CreateLoginStateCookie(HttpContext httpContext, LoginState loginState, string loginStateSecret, bool dangerouslyDisableSecureCookies)
    {
        // Clear any stale login state cookies and add a new one for the current request.
        ClearOldestLoginStateCookies(httpContext, dangerouslyDisableSecureCookies);

        // Encrypt the contents of the login state so it's not accessible in the browser.
        var encryptedLoginState = EncryptLoginState(loginState, loginStateSecret);

        // Add the new login state cookie (1 hour max age).
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            MaxAge = TimeSpan.FromHours(1),
            Path = "/",
            SameSite = SameSiteMode.Lax,
            Secure = !dangerouslyDisableSecureCookies,
        };
        var cookieName = $"{LoginStateCookiePrefix}{LoginStateCookieSeparator}{loginState.State}{LoginStateCookieSeparator}{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        httpContext.Response.Cookies.Append(cookieName, encryptedLoginState, cookieOptions);
    }

    /// <summary>
    /// Implements <see cref="ILoginStateHandler.GetAndClearLoginStateCookie"/>.
    /// </summary>
    /// <inheritdoc />
    public string GetAndClearLoginStateCookie(HttpContext httpContext, bool dangerouslyDisableSecureCookies)
    {
        // A login cookie is used to store the challenge code while the login process
        // is happening. Once the login process is complete, the cookie is no longer needed.
        var state = httpContext.Request.Query["state"].FirstOrDefault() ?? string.Empty;

        // This should resolve to a single cookie with this prefix or no cookie at all if it got cleared or expired.
        var matchingLoginStateCookies = httpContext.Request.Cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}{LoginStateCookieSeparator}{state}{LoginStateCookieSeparator}"))
            .OrderBy(c => long.Parse(c.Key?.Split(LoginStateCookieSeparator)[2] ?? string.Empty))
            .ToList();

        var allLoginStateCookies = httpContext.Request.Cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}{LoginStateCookieSeparator}"))
            .ToList();

        var loginStateCookie = string.Empty;

        if (matchingLoginStateCookies.Count > 0)
        {
            // Use the newest cookie matching the state
            loginStateCookie = matchingLoginStateCookies.Last().Value;
        }

        foreach (var cookie in allLoginStateCookies)
        {
            // httpContext.Response.Cookies.Delete(cookie.Key);
            httpContext.Response.Cookies.Append(cookie.Key, string.Empty, new CookieOptions
            {
                MaxAge = TimeSpan.Zero,
                Path = "/",
                SameSite = SameSiteMode.Lax,
                Secure = !dangerouslyDisableSecureCookies,
                HttpOnly = true,
            });
        }

        return loginStateCookie;
    }

    /// <summary>
    /// Implements <see cref="ILoginStateHandler.DecryptLoginState"/>.
    /// </summary>
    /// <inheritdoc />
    public LoginState DecryptLoginState(string encryptedState, string loginStateSecret)
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

    /// <summary>
    /// Implements <see cref="ILoginStateHandler.GenerateRandomString"/>.
    /// </summary>
    /// <inheritdoc />
    public string GenerateRandomString(int length)
    {
        using var rng = RandomNumberGenerator.Create();
        var randomBytes = new byte[length];
        rng.GetBytes(randomBytes);
        var base64 = Convert.ToBase64String(randomBytes);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private void ClearOldestLoginStateCookies(HttpContext httpContext, bool dangerouslyDisableSecureCookies)
    {
        // A login cookie is used to store the challenge code while the login process
        // is happening. Once the login process is complete, the cookie is no longer needed.
        var cookies = httpContext.Request.Cookies;
        var orderedLoginCookies = cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}{LoginStateCookieSeparator}"))
            .OrderBy(c =>
            {
                // Attempt to parse the index part of the key; handle parsing failure.
                var parts = c.Key.Split(LoginStateCookieSeparator);
                return parts.Length > 2 && long.TryParse(parts[2], out var result) ? result : long.MaxValue;
            })
            .ToList();

        if (orderedLoginCookies.Count < MaxNumberOfLoginStateCookies)
        {
            return;
        }

        // Delete the oldest login state cookies until we are back under the limit.
        // We retain 3 login cookies to support users opening the login page in multiple tabs.
        // Without this, each new login page would overwrite the previous cookie, breaking the flow for existing tabs.
        var numberOfCookiesToDelete = orderedLoginCookies.Count - MaxNumberOfLoginStateCookies + 1;
        for (var i = 0; i < numberOfCookiesToDelete; i++)
        {
            httpContext.Response.Cookies.Append(orderedLoginCookies[i].Key, string.Empty, new CookieOptions
            {
                MaxAge = TimeSpan.Zero,
                Path = "/",
                SameSite = SameSiteMode.Lax,
                Secure = !dangerouslyDisableSecureCookies,
                HttpOnly = true,
            });
        }
    }

    // NOTE: Create LoginStateSecret via `openssl rand -base64 32`
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
}
