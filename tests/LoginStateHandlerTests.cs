using System.Security.Cryptography;
using System.Text.Json;
using System.Web;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class LoginStateHandlerTests
{
    // Generate a 43-character random string (32 bytes base64url without padding)
    private static readonly string TestLoginStateSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    private static readonly ILoginStateHandler mLoginStateHandler = new LoginStateHandler();

    [Fact]
    public void CreateLoginState_WithValidInput_ReturnsLoginState()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var redirectUri = "https://example.com/callback";
        var returnUrl = "/dashboard";
        var customState = new Dictionary<string, object> { { "test", "value" } };

        var result = mLoginStateHandler.CreateLoginState(httpContext, redirectUri, returnUrl, customState);

        Assert.NotNull(result);
        Assert.Equal(43, result.State.Length); // Base64 encoded 32 bytes
        Assert.Equal(43, result.CodeVerifier.Length);
        Assert.Equal(redirectUri, result.RedirectUri);
        Assert.Equal(returnUrl, result.ReturnUrl);
        Assert.Equal(customState, result.CustomState);
    }

    [Fact]
    public void CreateLoginStateCookie_CreatesValidCookie()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var loginState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            string.Empty,
            null);

        mLoginStateHandler.CreateLoginStateCookie(
            httpContext,
            loginState,
            TestLoginStateSecret,
            false);

        var cookies = httpContext.Response.Headers.GetCommaSeparatedValues("Set-Cookie");
        var loginStateCookie = cookies.Single(c => c.StartsWith("login#state123#"));

        Assert.NotNull(loginStateCookie);
        Assert.Contains("httponly", loginStateCookie);
        Assert.Contains("max-age=3600", loginStateCookie);
        Assert.Contains("path=/", loginStateCookie);
        Assert.Contains("samesite=lax", loginStateCookie);
        Assert.Contains("secure", loginStateCookie);
    }

    [Fact]
    public void GetAndClearLoginStateCookie_ReturnsAndClearsCookie()
    {
        var cookies = new Dictionary<string, string>();
        var timestamp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeMilliseconds();
        cookies.Add($"login#testState#{timestamp}", "encryptedValue");

        var httpContext = TestUtils.setupHttpContext(
            "example.com",
            queryString: $"state=testState",
            requestCookies: cookies
        );

        var loginStateCookie = mLoginStateHandler.GetAndClearLoginStateCookie(httpContext, false);

        Assert.Equal("encryptedValue", loginStateCookie);

        var deletedCookies = httpContext.Response.Headers.GetCommaSeparatedValues("Set-Cookie")
            .Where(c => c.Contains("max-age=0", StringComparison.OrdinalIgnoreCase))
            .Select(c => c.Split('=')[0].Trim())
            .ToList();

        Assert.Single(deletedCookies);
        Assert.True(deletedCookies.Any(c => c.StartsWith("login#testState#")), "Expected a deleted cookie with prefix 'login#testState#'");
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_PreservesLoginState()
    {
        var originalState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            "/dashboard",
            new Dictionary<string, object> { { "test", "value" } });
        var httpContext = TestUtils.setupHttpContext("example.com");

        mLoginStateHandler.CreateLoginStateCookie(httpContext, originalState, TestLoginStateSecret, true);

        var cookies = httpContext.Response.Headers.GetCommaSeparatedValues("Set-Cookie");
        var loginStateCookie = cookies.Single(c => c.StartsWith("login#state123#"));

        Assert.NotNull(loginStateCookie);
        Assert.Contains("httponly", loginStateCookie);
        Assert.Contains("max-age=3600", loginStateCookie);
        Assert.Contains("path=/", loginStateCookie);
        Assert.Contains("samesite=lax", loginStateCookie);
        Assert.DoesNotContain("secure", loginStateCookie);

        var encryptedValue = loginStateCookie.Split(";")[0].Split("=")[1];
        Assert.NotNull(encryptedValue);

        // HttpContext URL encodes the cookie value, so need to URL decode here.
        var decodedEncryptedValue = HttpUtility.UrlDecode(encryptedValue);
        var decryptedState = mLoginStateHandler.DecryptLoginState(decodedEncryptedValue, TestLoginStateSecret);

        Assert.Equal(originalState.State, decryptedState.State);
        Assert.Equal(originalState.CodeVerifier, decryptedState.CodeVerifier);
        Assert.Equal(originalState.RedirectUri, decryptedState.RedirectUri);
        Assert.Equal(originalState.ReturnUrl, decryptedState.ReturnUrl);
        Assert.Equal(
            JsonSerializer.Serialize(originalState.CustomState),
            JsonSerializer.Serialize(decryptedState.CustomState));
    }

    [Fact]
    public void CreateLoginStateCookie_WithSecretTooShort_ThrowsArgumentException()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var loginState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            string.Empty,
            null);

        // Secret with only 20 characters (less than required 32)
        var shortSecret = "abcdefghijklmnopqrst";

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.CreateLoginStateCookie(httpContext, loginState, shortSecret, false));
        Assert.Contains("must be at least 32 characters long", ex.Message);
    }

    [Fact]
    public void CreateLoginStateCookie_WithEmptySecret_ThrowsArgumentException()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var loginState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            string.Empty,
            null);

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.CreateLoginStateCookie(httpContext, loginState, "", false));
        Assert.Contains("must be at least 32 characters long", ex.Message);
    }

    [Fact]
    public void CreateLoginStateCookie_WithNullSecret_ThrowsArgumentException()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var loginState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            string.Empty,
            null);

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.CreateLoginStateCookie(httpContext, loginState, null!, false));
        Assert.Contains("must be at least 32 characters long", ex.Message);
    }

    [Fact]
    public void DecryptLoginState_WithSecretTooShort_ThrowsArgumentException()
    {
        var shortSecret = "abcdefghijklmnopqrst";
        var encryptedState = "someEncryptedValue|someIV";

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.DecryptLoginState(encryptedState, shortSecret));
        Assert.Contains("must be at least 32 characters long", ex.Message);
    }

    [Fact]
    public void DecryptLoginState_WithEmptySecret_ThrowsArgumentException()
    {
        var encryptedState = "someEncryptedValue|someIV";

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.DecryptLoginState(encryptedState, ""));
        Assert.Contains("must be at least 32 characters long", ex.Message);
    }

    [Fact]
    public void DecryptLoginState_WithNullSecret_ThrowsArgumentException()
    {
        var encryptedState = "someEncryptedValue|someIV";

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.DecryptLoginState(encryptedState, null!));
        Assert.Contains("must be at least 32 characters long", ex.Message);
    }

    [Fact]
    public void DecryptLoginState_WithInvalidEncryptedStateFormat_ThrowsArgumentException()
    {
        var invalidEncryptedState = "invalidFormatWithoutPipe";

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.DecryptLoginState(invalidEncryptedState, TestLoginStateSecret));
        Assert.Contains("Invalid encrypted state format", ex.Message);
    }

    [Fact]
    public void CreateLoginStateCookie_WithExactly32CharSecret_Works()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var loginState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            string.Empty,
            null);

        // Exactly 32 characters
        var exactSecret = "abcdefghijklmnopqrstuvwxyz123456";
        Assert.Equal(32, exactSecret.Length);

        // Should not throw
        mLoginStateHandler.CreateLoginStateCookie(httpContext, loginState, exactSecret, false);

        var cookies = httpContext.Response.Headers.GetCommaSeparatedValues("Set-Cookie");
        var loginStateCookie = cookies.Single(c => c.StartsWith("login#state123#"));
        Assert.NotNull(loginStateCookie);
    }

    [Fact]
    public void CreateLoginStateCookie_WithLongSecret_Works()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var loginState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            string.Empty,
            null);

        // Much longer than 32 characters
        var longSecret = "abcdefghijklmnopqrstuvwxyz123456789012345678901234567890";
        Assert.True(longSecret.Length > 32);

        // Should work fine - uses SHA256 to derive 32-byte key
        mLoginStateHandler.CreateLoginStateCookie(httpContext, loginState, longSecret, false);

        var cookies = httpContext.Response.Headers.GetCommaSeparatedValues("Set-Cookie");
        var loginStateCookie = cookies.Single(c => c.StartsWith("login#state123#"));
        Assert.NotNull(loginStateCookie);
    }

    [Fact]
    public void ClearOldestLoginStateCookies_RemovesOldestWhenLimitExceeded()
    {
        var now = DateTimeOffset.UtcNow;
        var cookies = new Dictionary<string, string>();

        // Add 4 cookies (exceeding the limit of 3)
        for (int i = 0; i < 4; i++)
        {
            var timestamp = now.AddMinutes(-i).ToUnixTimeMilliseconds();
            cookies.Add($"login#state{i}#{timestamp}", $"value{i}");
        }

        var httpContext = TestUtils.setupHttpContext("example.com", requestCookies: cookies);

        var loginState = new LoginState(
            "newState",
            "verifier",
            "https://example.com/callback",
            string.Empty,
            null);
        mLoginStateHandler.CreateLoginStateCookie(httpContext, loginState, TestLoginStateSecret, false);

        var deletedCookies = httpContext.Response.Headers.GetCommaSeparatedValues("Set-Cookie")
            .Where(c => c.Contains("max-age=0", StringComparison.OrdinalIgnoreCase))
            .Select(c => c.Split('=')[0].Trim())
            .ToList();

        Assert.Equal(2, deletedCookies.Count);
        Assert.True(deletedCookies.Any(c => c.StartsWith("login#state3#")), "Expected a deleted cookie with prefix 'login#state3#'");
        Assert.True(deletedCookies.Any(c => c.StartsWith("login#state2#")), "Expected a deleted cookie with prefix 'login#state2#'");
    }

    [Fact]
    public void CreateLoginState_WithNullReturnUrl_SetsNullReturnUrl()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var redirectUri = "https://example.com/callback";

        var result = mLoginStateHandler.CreateLoginState(httpContext, redirectUri, null, null);

        Assert.Null(result.ReturnUrl);
    }

    [Fact]
    public void GetAndClearLoginStateCookie_WithNoStateParam_ReturnsEmptyString()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");

        var result = mLoginStateHandler.GetAndClearLoginStateCookie(httpContext, false);

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void GetAndClearLoginStateCookie_WithMultipleMatchingCookies_ReturnsNewest()
    {
        var cookies = new Dictionary<string, string>();
        var olderTimestamp = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeMilliseconds();
        var newerTimestamp = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeMilliseconds();

        cookies.Add($"login#testState#{olderTimestamp}", "olderValue");
        cookies.Add($"login#testState#{newerTimestamp}", "newerValue");

        var httpContext = TestUtils.setupHttpContext(
            "example.com",
            queryString: "state=testState",
            requestCookies: cookies
        );

        var result = mLoginStateHandler.GetAndClearLoginStateCookie(httpContext, false);

        Assert.Equal("newerValue", result);
    }
}
