using System.Security.Cryptography;
using System.Text.Json;
using System.Web;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class LoginStateHandlerTests
{
    private static readonly string TestLoginStateSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static readonly ILoginStateHandler mLoginStateHandler = new LoginStateHandler();

    [Fact]
    public void CreateLoginState_WithValidInput_ReturnsLoginState()
    {
        var httpContext = TestUtils.setupHttpContext("example.com");
        var redirectUri = "https://example.com/callback";
        var customState = new Dictionary<string, object> { { "test", "value" } };

        var result = mLoginStateHandler.CreateLoginState(httpContext, redirectUri, customState);

        Assert.NotNull(result);
        Assert.Equal(43, result.State.Length); // Base64 encoded 32 bytes
        Assert.Equal(43, result.CodeVerifier.Length);
        Assert.Equal(redirectUri, result.RedirectUri);
        Assert.Empty(result.ReturnUrl!);
        Assert.Equal(customState, result.CustomState);
    }

    [Fact]
    public void CreateLoginState_WithReturnUrl_IncludesReturnUrl()
    {
        var redirectUri = "https://example.com/callback";
        var returnUrl = "/dashboard";
        var httpContext = TestUtils.setupHttpContext(
            "example.com",
            queryString: $"return_url={returnUrl}"
        );

        var result = mLoginStateHandler.CreateLoginState(httpContext, redirectUri, null);

        Assert.Equal(returnUrl, result.ReturnUrl);
    }

    [Fact]
    public void CreateLoginState_WithMultipleReturnUrls_ThrowsArgumentException()
    {
        var redirectUri = "https://example.com/callback";
        var httpContext = TestUtils.setupHttpContext("example.com");
        httpContext.Request.QueryString = new QueryString("?return_url=/dashboard&return_url=/profile");

        Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.CreateLoginState(httpContext, redirectUri, null));
    }

    [Fact]
    public void CreateLoginState_WithSpacesInReturnUrl_ThrowsArgumentException()
    {
        var returnUrl = "/dash board";
        var httpContext = TestUtils.setupHttpContext(
            "example.com",
            queryString: $"return_url={returnUrl}"
        );
        var redirectUri = "https://example.com/callback";

        Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.CreateLoginState(httpContext, redirectUri, null));
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
    public void DecryptLoginState_WithInvalidSecret_ThrowsArgumentException()
    {
        // Use a valid base64 string that decodes to wrong length
        var invalidSecret = Convert.ToBase64String(new byte[] { 1, 2, 3 });
        var loginState = new LoginState(
            "state123",
            "verifier123",
            "https://example.com/callback",
            string.Empty,
            null);

        var httpContext = TestUtils.setupHttpContext("example.com");

        var ex = Assert.Throws<ArgumentException>(() =>
            mLoginStateHandler.CreateLoginStateCookie(httpContext, loginState, invalidSecret, false));
        Assert.Contains("Invalid key size", ex.Message);
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
}
