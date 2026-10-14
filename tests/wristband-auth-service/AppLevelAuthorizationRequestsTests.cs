using System.Reflection;

using Microsoft.AspNetCore.Http;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class AppLevelAuthorizationRequestsTests
{
    private const string VanityDomain = "auth.example.com";
    private const string RootDomain = "business.invotastic.com";
    private const string LoginStateSecret = "this-is-a-very-long-login-state-secret-1234";

    private readonly Mock<IWristbandApiClient> _mockApiClient;

    public AppLevelAuthorizationRequestsTests()
    {
        _mockApiClient = new Mock<IWristbandApiClient>();
        _mockApiClient
            .Setup(m => m.GetTokens(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(new WristbandTokenResponse { AccessToken = "access-token", IdToken = "id-token", ExpiresIn = 3600 });
        _mockApiClient
            .Setup(m => m.GetUserinfo(It.IsAny<string>()))
            .ReturnsAsync(UserInfo.Empty);
    }

    // ////////////////////////////////////
    //  LOGIN
    // ////////////////////////////////////

    [Fact]
    public async Task Login_WithUnresolvedTenant_RedirectsToAppLevelAuthorizeEndpointWithRootDomainCookie()
    {
        var service = CreateService();
        var httpContext = TestUtils.setupHttpContext(RootDomain, "return_url=/settings&login_hint=a@b.com");

        var authorizeUrl = await service.Login(httpContext, new LoginConfig());

        var uri = new Uri(authorizeUrl);
        Assert.Equal(VanityDomain, uri.Host);
        Assert.Equal("/api/v1/oauth2/authorize", uri.AbsolutePath);
        Assert.Contains("login_hint=a%40b.com", uri.Query);

        var cookie = Assert.Single(LoginStateSetCookies(httpContext));
        Assert.Contains($"domain=.{RootDomain}", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_WithUnresolvedTenantAndNoTenantSubdomains_SetsHostOnlyCookie()
    {
        var service = CreateService(useTenantSubdomains: false);
        var httpContext = TestUtils.setupHttpContext(RootDomain);

        var authorizeUrl = await service.Login(httpContext, new LoginConfig());

        Assert.StartsWith($"https://{VanityDomain}/api/v1/oauth2/authorize?", authorizeUrl);
        var cookie = Assert.Single(LoginStateSetCookies(httpContext));
        Assert.DoesNotContain("domain=", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_WithCustomApplicationLoginPageUrl_HasNoEffectWhenEnabled()
    {
        var service = CreateService(customApplicationLoginPageUrl: "https://custom.example.com/login");
        var httpContext = TestUtils.setupHttpContext(RootDomain);

        var authorizeUrl = await service.Login(httpContext, new LoginConfig());

        Assert.StartsWith($"https://{VanityDomain}/api/v1/oauth2/authorize?", authorizeUrl);
    }

    [Fact]
    public async Task Login_WithResolvedTenant_UsesTenantLevelFlowWithRootDomainCookie()
    {
        var service = CreateService();
        var httpContext = TestUtils.setupHttpContext($"devs4you.{RootDomain}");

        var authorizeUrl = await service.Login(httpContext, new LoginConfig());

        Assert.StartsWith($"https://devs4you-{VanityDomain}/api/v1/oauth2/authorize?", authorizeUrl);
        var cookie = Assert.Single(LoginStateSetCookies(httpContext));
        Assert.Contains($"domain=.{RootDomain}", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_WhenDisabled_UsesHostOnlyCookieAndAppLoginPage()
    {
        var service = CreateService(applicationAuthorizationRequestsEnabled: false);

        var tenantContext = TestUtils.setupHttpContext($"devs4you.{RootDomain}");
        await service.Login(tenantContext, new LoginConfig());
        var cookie = Assert.Single(LoginStateSetCookies(tenantContext));
        Assert.DoesNotContain("domain=", cookie, StringComparison.OrdinalIgnoreCase);

        var rootContext = TestUtils.setupHttpContext(RootDomain, "return_url=/a?b=c");
        var loginPageUrl = await service.Login(rootContext, new LoginConfig());
        Assert.Equal($"https://{VanityDomain}/login?client_id=test-client&state=%2Fa%3Fb%3Dc", loginPageUrl);
        Assert.Empty(LoginStateSetCookies(rootContext));
    }

    // ////////////////////////////////////
    //  CALLBACK
    // ////////////////////////////////////

    [Theory]
    [InlineData(null, "/settings?tab=billing", "/settings?tab=billing")]
    [InlineData(null, "https://devs4you.business.invotastic.com/dashboard", "https://devs4you.business.invotastic.com/dashboard")]
    [InlineData(null, "https://business.invotastic.com/dashboard?tab=1", "https://devs4you.business.invotastic.com/dashboard?tab=1")]
    [InlineData(false, "https://business.invotastic.com/dashboard", "https://business.invotastic.com/dashboard")]
    [InlineData(null, "https://evil.com/phish", null)]
    [InlineData(null, "//evil.com/phish", null)]
    [InlineData(null, "/\\evil.com", null)]
    [InlineData(null, "https://other.business.invotastic.com/dashboard", null)]
    [InlineData(null, "http://devs4you.business.invotastic.com/dashboard", null)]
    [InlineData(null, "javascript:alert(1)", null)]
    public async Task Callback_ValidatesReturnUrl(bool? appLevelEnabled, string returnUrl, string? expected)
    {
        var service = CreateService(applicationAuthorizationRequestsEnabled: appLevelEnabled);
        var httpContext = CreateCallbackContext(CreateLoginState(returnUrl), LoginStateSecret);

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.Completed, result.Type);
        Assert.Equal(expected, result.CallbackData.ReturnUrl);
        Assert.Equal("devs4you", result.CallbackData.TenantName);
    }

    [Fact]
    public async Task Callback_ClearsLoginStateCookiesOnRootDomain()
    {
        var service = CreateService();
        var httpContext = CreateCallbackContext(CreateLoginState(null), LoginStateSecret);

        await service.Callback(httpContext);

        var cleared = Assert.Single(LoginStateSetCookies(httpContext));
        Assert.Contains($"domain=.{RootDomain}", cleared, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("max-age=0", cleared, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Callback_WithCookieEncryptedWithDifferentSecret_ReturnsInvalidLoginState()
    {
        var service = CreateService();
        var httpContext = CreateCallbackContext(CreateLoginState(null), new string('z', 40));

        var result = await service.Callback(httpContext);

        AssertInvalidLoginState(result);
    }

    [Fact]
    public async Task Callback_WithMalformedCookie_ReturnsInvalidLoginState()
    {
        var service = CreateService();
        var httpContext = TestUtils.setupHttpContext(
            $"devs4you.{RootDomain}",
            "state=test-state&code=test-code",
            new Dictionary<string, string> { { $"login#test-state#{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}", "not-encrypted" } });

        var result = await service.Callback(httpContext);

        AssertInvalidLoginState(result);
    }

    [Theory]
    [InlineData(-3661)]
    [InlineData(61)]
    public async Task Callback_WithLoginStateOutsideItsLifetime_ReturnsInvalidLoginState(int ageOffsetSeconds)
    {
        var service = CreateService();
        var loginState = CreateLoginState(null);
        loginState.CreatedAt = DateTimeOffset.UtcNow.AddSeconds(ageOffsetSeconds).ToUnixTimeMilliseconds();
        var httpContext = CreateCallbackContext(loginState, LoginStateSecret);

        var result = await service.Callback(httpContext);

        AssertInvalidLoginState(result);
    }

    [Fact]
    public async Task Callback_WithLoginStateWithinClockSkew_Completes()
    {
        var service = CreateService();
        var loginState = CreateLoginState(null);
        loginState.CreatedAt = DateTimeOffset.UtcNow.AddSeconds(-3659).ToUnixTimeMilliseconds();
        var httpContext = CreateCallbackContext(loginState, LoginStateSecret);

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.Completed, result.Type);
    }

    // ////////////////////////////////////
    //  LOGOUT
    // ////////////////////////////////////

    [Theory]
    [InlineData(true, null, null, null, "https://business.invotastic.com/api/auth/login")]
    [InlineData(false, null, null, null, "https://business.invotastic.com/api/auth/login")]
    [InlineData(true, null, null, "https://redirect.example.com", "https://redirect.example.com")]
    [InlineData(true, null, "https://custom.example.com/login", null, "https://business.invotastic.com/api/auth/login")]
    [InlineData(true, false, null, null, "https://auth.example.com/login?client_id=test-client")]
    [InlineData(true, false, "https://custom.example.com/login", null, "https://custom.example.com/login?client_id=test-client")]
    public async Task Logout_WithUnresolvedTenant_UsesExpectedFallback(
        bool useTenantSubdomains,
        bool? appLevelEnabled,
        string? customApplicationLoginPageUrl,
        string? redirectUrl,
        string expected)
    {
        var service = CreateService(useTenantSubdomains, appLevelEnabled, customApplicationLoginPageUrl);
        var httpContext = TestUtils.setupHttpContext(RootDomain);

        var logoutUrl = await service.Logout(httpContext, new LogoutConfig { RedirectUrl = redirectUrl });

        Assert.Equal(expected, logoutUrl);
    }

    // ////////////////////////////////////
    //  HELPERS
    // ////////////////////////////////////

    private static void AssertInvalidLoginState(CallbackResult result)
    {
        Assert.Equal(CallbackResultType.RedirectRequired, result.Type);
        Assert.Equal(CallbackFailureReason.InvalidLoginState, result.Reason);
        Assert.Equal($"https://devs4you.{RootDomain}/api/auth/login", result.RedirectUrl);
    }

    private static LoginState CreateLoginState(string? returnUrl)
    {
        return new LoginState("test-state", "test-code-verifier", $"https://devs4you.{RootDomain}/api/auth/callback", returnUrl, null);
    }

    private static List<string> LoginStateSetCookies(HttpContext httpContext)
    {
        return httpContext.Response.Headers.SetCookie
            .Where(c => c != null && c.StartsWith("login", StringComparison.Ordinal))
            .Select(c => c!)
            .ToList();
    }

    private static HttpContext CreateCallbackContext(LoginState loginState, string loginStateSecret)
    {
        // Encrypt the login state the same way the SDK does by writing it to a throwaway response.
        var loginContext = TestUtils.setupHttpContext($"devs4you.{RootDomain}");
        new LoginStateHandler().CreateLoginStateCookie(loginContext, loginState, loginStateSecret, false, null);
        var setCookie = loginContext.Response.Headers.SetCookie.ToString();
        var cookieName = setCookie.Substring(0, setCookie.IndexOf('='));
        var cookieValue = Uri.UnescapeDataString(setCookie.Substring(setCookie.IndexOf('=') + 1).Split(';')[0]);

        return TestUtils.setupHttpContext(
            $"devs4you.{RootDomain}",
            "state=test-state&code=test-code",
            new Dictionary<string, string> { { cookieName, cookieValue } });
    }

    private WristbandAuthService CreateService(
        bool useTenantSubdomains = true,
        bool? applicationAuthorizationRequestsEnabled = null,
        string? customApplicationLoginPageUrl = null)
    {
        var host = useTenantSubdomains ? $"{{tenant_name}}.{RootDomain}" : RootDomain;
        var service = new WristbandAuthService(new WristbandAuthConfig
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            LoginStateSecret = LoginStateSecret,
            LoginUrl = $"https://{host}/api/auth/login",
            RedirectUri = $"https://{host}/api/auth/callback",
            WristbandApplicationVanityDomain = VanityDomain,
            CustomApplicationLoginPageUrl = customApplicationLoginPageUrl,
            ApplicationAuthorizationRequestsEnabled = applicationAuthorizationRequestsEnabled,
            AutoConfigureEnabled = false,
        });

        typeof(WristbandAuthService)
            .GetField("_wristbandApiClient", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(service, _mockApiClient.Object);
        return service;
    }
}
