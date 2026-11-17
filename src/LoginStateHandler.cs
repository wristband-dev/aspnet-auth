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
    private const int NonceSize = 12; // 96 bits (recommended for AES-GCM per NIST SP 800-38D)
    private const int TagSize = 16; // 128 bits (GCM authentication tag)

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
    public LoginState CreateLoginState(
        HttpContext httpContext,
        string redirectUri,
        string? returnUrl,
        Dictionary<string, object>? customState)
    {
        return new LoginState(
            state: GenerateRandomString(32),
            codeVerifier: GenerateRandomString(32),
            redirectUri: redirectUri,
            returnUrl: returnUrl,
            customState: customState);
    }

    /// <summary>
    /// Implements <see cref="ILoginStateHandler.CreateLoginStateCookie"/>.
    /// </summary>
    /// <inheritdoc />
    public void CreateLoginStateCookie(HttpContext httpContext, LoginState loginState, string loginStateSecret, bool dangerouslyDisableSecureCookies, string? cookieDomain)
    {
        // Clear any stale login state cookies and add a new one for the current request.
        ClearOldestLoginStateCookies(httpContext, dangerouslyDisableSecureCookies, cookieDomain);

        // Encrypt the contents of the login state so it's not accessible in the browser.
        var encryptedLoginState = EncryptLoginState(loginState, loginStateSecret);

        // Add the new login state cookie (1 hour max age).
        var cookieOptions = new CookieOptions
        {
            Domain = cookieDomain,
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
    public string GetAndClearLoginStateCookie(HttpContext httpContext, bool dangerouslyDisableSecureCookies, string? cookieDomain)
    {
        // A login cookie is used to store the challenge code while the login process
        // is happening. Once the login process is complete, the cookie is no longer needed.
        var state = httpContext.Request.Query["state"].FirstOrDefault() ?? string.Empty;

        // This should resolve to a single cookie with this prefix or no cookie at all if it got cleared or expired.
        var matchingLoginStateCookies = httpContext.Request.Cookies
            .Where(c => c.Key.StartsWith($"{LoginStateCookiePrefix}{LoginStateCookieSeparator}{state}{LoginStateCookieSeparator}"))
            .OrderBy(c => GetCookieCreationTime(c.Key))
            .ToList();

        var loginStateCookie = string.Empty;

        if (matchingLoginStateCookies.Count > 0)
        {
            // Use the newest cookie matching the state
            loginStateCookie = matchingLoginStateCookies.Last().Value;
        }

        // Only clear the cookies for this state. Login state cookies for other states belong to logins that were
        // started in other tabs and haven't finished yet.
        foreach (var cookie in matchingLoginStateCookies)
        {
            httpContext.Response.Cookies.Append(cookie.Key, string.Empty, new CookieOptions
            {
                Domain = cookieDomain,
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
        if (string.IsNullOrEmpty(loginStateSecret) || loginStateSecret.Length < 32)
        {
            throw new ArgumentException("Login state secret must be at least 32 characters long");
        }

        // Format: [nonce:12][auth_tag:16][ciphertext:variable], base64 encoded.
        var encrypted = Convert.FromBase64String(encryptedState);
        if (encrypted.Length < NonceSize + TagSize)
        {
            throw new ArgumentException("Invalid encrypted state format");
        }

        var nonce = encrypted.AsSpan(0, NonceSize);
        var tag = encrypted.AsSpan(NonceSize, TagSize);
        var ciphertext = encrypted.AsSpan(NonceSize + TagSize);
        var decrypted = new byte[ciphertext.Length];

        // Throws AuthenticationTagMismatchException (a CryptographicException) when the cookie was changed.
        using var aes = new AesGcm(DeriveKey(loginStateSecret), TagSize);
        aes.Decrypt(nonce, ciphertext, tag, decrypted);

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

    // Hashes the whole secret into a 32-byte AES-256 key, so that no part of a secret longer than 32 characters is
    // ignored.
    private static byte[] DeriveKey(string loginStateSecret)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(loginStateSecret));
    }

    private static long GetCookieCreationTime(string cookieName)
    {
        var parts = cookieName.Split(LoginStateCookieSeparator);
        return parts.Length > 2 && long.TryParse(parts[2], out var result) ? result : long.MaxValue;
    }

    private void ClearOldestLoginStateCookies(HttpContext httpContext, bool dangerouslyDisableSecureCookies, string? cookieDomain)
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
                Domain = cookieDomain,
                MaxAge = TimeSpan.Zero,
                Path = "/",
                SameSite = SameSiteMode.Lax,
                Secure = !dangerouslyDisableSecureCookies,
                HttpOnly = true,
            });
        }
    }

    private string EncryptLoginState(LoginState loginState, string loginStateSecret)
    {
        if (string.IsNullOrEmpty(loginStateSecret) || loginStateSecret.Length < 32)
        {
            throw new ArgumentException("Login state secret must be at least 32 characters long");
        }

        var plaintext = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(loginState));

        // Format: [nonce:12][auth_tag:16][ciphertext:variable], base64 encoded. AES-GCM signs the ciphertext as well
        // as encrypting it, so any change to the cookie is detected when it is decrypted.
        var encrypted = new byte[NonceSize + TagSize + plaintext.Length];
        var nonce = encrypted.AsSpan(0, NonceSize);
        var tag = encrypted.AsSpan(NonceSize, TagSize);
        var ciphertext = encrypted.AsSpan(NonceSize + TagSize);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(DeriveKey(loginStateSecret), TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        return Convert.ToBase64String(encrypted);
    }
}
