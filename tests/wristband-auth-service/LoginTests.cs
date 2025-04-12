using System.Reflection;
using System.Security.Cryptography;
using System.Web;

using Microsoft.AspNetCore.Http;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class LoginTests
{
    private readonly Mock<ILoginStateHandler> _mockLoginStateHandler;
    private readonly Mock<IWristbandApiClient> _mockApiClient;
    private readonly WristbandAuthConfig _defaultConfig;

    public LoginTests()
    {
        _defaultConfig = new WristbandAuthConfig
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            LoginStateSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://app.example.com/callback",
            WristbandApplicationDomain = "wristband.example.com"
        };

        _mockLoginStateHandler = new Mock<ILoginStateHandler>();
        _mockApiClient = new Mock<IWristbandApiClient>();
        SetupDefaultLoginStateMock();
    }

    [Fact]
    public async Task Login_WithNoTenantInfo_ReturnsAppLevelLoginUrl()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = _defaultConfig.LoginUrl,
            RedirectUri = _defaultConfig.RedirectUri,
            WristbandApplicationDomain = _defaultConfig.WristbandApplicationDomain,
            UseCustomDomains = false,
            UseTenantSubdomains = false,
        };
        var service = SetupWristbandAuthService(config);
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        var result = await service.Login(httpContext, null);

        var expectedUrl = $"https://{_defaultConfig.WristbandApplicationDomain}/login?client_id={_defaultConfig.ClientId}";
        Assert.Equal(expectedUrl, result);
    }

    [Fact]
    public async Task Login_WithCustomApplicationLoginPage_UsesCustomUrl()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = _defaultConfig.LoginUrl,
            RedirectUri = _defaultConfig.RedirectUri,
            WristbandApplicationDomain = _defaultConfig.WristbandApplicationDomain,
            CustomApplicationLoginPageUrl = "https://custom.example.com/login"
        };
        var service = SetupWristbandAuthService(config);
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        var result = await service.Login(httpContext, null);

        Assert.Equal($"https://custom.example.com/login?client_id={config.ClientId}", result);
    }

    [Fact]
    public async Task Login_WithTenantCustomDomain_HasHighestPriority()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = "https://{tenant_domain}.example.com/login",
            RedirectUri = "https://{tenant_domain}.example.com/callback",
            WristbandApplicationDomain = _defaultConfig.WristbandApplicationDomain,
            UseTenantSubdomains = true,
            RootDomain = "example.com"
        };
        var service = SetupWristbandAuthService(config);
        var customDomain = "tenant.custom.com";

        var httpContext = TestUtils.setupHttpContext(
            "tenant1.example.com", // Even with a valid tenant subdomain
            $"tenant_custom_domain={customDomain}"); // Custom domain should take precedence

        var result = await service.Login(httpContext, null);

        Assert.StartsWith($"https://{customDomain}/api/v1/oauth2/authorize?", result);
    }

    [Fact]
    public async Task Login_WithTenantSubdomain_TakesPrecedenceOverQueryParam()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = "https://{tenant_domain}.example.com/login",
            RedirectUri = "https://{tenant_domain}.example.com/callback",
            WristbandApplicationDomain = _defaultConfig.WristbandApplicationDomain,
            UseTenantSubdomains = true,
            RootDomain = "example.com"
        };
        var service = SetupWristbandAuthService(config);

        var httpContext = TestUtils.setupHttpContext(
            "tenant1.example.com",
            "tenant_domain=tenant2"); // Should be ignored in favor of subdomain

        var result = await service.Login(httpContext, null);

        Assert.Contains("tenant1", result);
        Assert.DoesNotContain("tenant2", result);
    }

    [Fact]
    public async Task Login_WithTenantDomainQueryParam_ReturnsCorrectUrl()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = _defaultConfig.LoginUrl,
            RedirectUri = _defaultConfig.RedirectUri,
            WristbandApplicationDomain = _defaultConfig.WristbandApplicationDomain,
            UseTenantSubdomains = false,
            UseCustomDomains = false
        };
        var service = SetupWristbandAuthService(config);
        var tenantDomain = "mytenant";
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain={tenantDomain}");

        var result = await service.Login(httpContext, null);

        var expectedUrl = $"https://{tenantDomain}-{_defaultConfig.WristbandApplicationDomain}/api/v1/oauth2/authorize";
        Assert.StartsWith(expectedUrl, result);

        var uri = new Uri(result);
        var query = HttpUtility.ParseQueryString(uri.Query);
        Assert.Equal(_defaultConfig.ClientId, query["client_id"]);
        Assert.Equal(_defaultConfig.RedirectUri, query["redirect_uri"]);
        Assert.Equal("code", query["response_type"]);
        Assert.NotNull(query["state"]);
    }

    [Fact]
    public async Task Login_WithDefaultTenantCustomDomain_UsesDefaultWhenNoOtherDomainSpecified()
    {
        var defaultCustomDomain = "default.custom.com";
        var loginConfig = new LoginConfig { DefaultTenantCustomDomain = defaultCustomDomain };
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        var result = await service.Login(httpContext, loginConfig);

        Assert.StartsWith($"https://{defaultCustomDomain}/api/v1/oauth2/authorize?", result);
    }

    [Fact]
    public async Task Login_WithDefaultTenantDomainName_UsesDefaultWhenNoOtherDomainSpecified()
    {
        var defaultTenantName = "default-tenant";
        var loginConfig = new LoginConfig { DefaultTenantDomainName = defaultTenantName };
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        var result = await service.Login(httpContext, loginConfig);

        Assert.StartsWith($"https://{defaultTenantName}-{_defaultConfig.WristbandApplicationDomain}/api/v1/oauth2/authorize?", result);
    }

    [Fact]
    public async Task Login_WithCustomDomains_UsesDotSeparator()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = _defaultConfig.LoginUrl,
            RedirectUri = _defaultConfig.RedirectUri,
            WristbandApplicationDomain = _defaultConfig.WristbandApplicationDomain,
            UseCustomDomains = true
        };
        var service = SetupWristbandAuthService(config);
        var tenantDomain = "tenant1";
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain={tenantDomain}");

        var result = await service.Login(httpContext, null);

        Assert.Contains($"{tenantDomain}.{config.WristbandApplicationDomain}", result);
    }

    [Fact]
    public async Task Login_WithoutCustomDomains_UsesHyphenSeparator()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var tenantDomain = "tenant1";
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain={tenantDomain}");

        var result = await service.Login(httpContext, null);

        Assert.Contains($"{tenantDomain}-{_defaultConfig.WristbandApplicationDomain}", result);
    }

    [Fact]
    public async Task Login_WithLoginHint_IncludesInAuthorizationUrl()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var loginHint = "user@example.com";
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain=tenant1&login_hint={Uri.EscapeDataString(loginHint)}");

        var result = await service.Login(httpContext, null);

        Assert.Contains($"login_hint={Uri.EscapeDataString(loginHint)}", result);
    }

    [Fact]
    public async Task Login_WithAdditionalScopes_IncludesAllScopes()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = _defaultConfig.LoginUrl,
            RedirectUri = _defaultConfig.RedirectUri,
            WristbandApplicationDomain = _defaultConfig.WristbandApplicationDomain,
            Scopes = new List<string> { "openid", "offline_access", "email", "profile", "custom_scope" }
        };
        var service = SetupWristbandAuthService(config);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "tenant_domain=tenant1");

        var result = await service.Login(httpContext, null);

        var uri = new Uri(result);
        var query = HttpUtility.ParseQueryString(uri.Query);
        var scopes = query["scope"]?.Split(' ') ?? Array.Empty<string>();
        Assert.Contains("openid", scopes);
        Assert.Contains("offline_access", scopes);
        Assert.Contains("email", scopes);
        Assert.Contains("profile", scopes);
        Assert.Contains("custom_scope", scopes);
    }

    private WristbandAuthService SetupWristbandAuthService(WristbandAuthConfig authConfig)
    {
        var wristbandAuthService = new WristbandAuthService(authConfig);

        var fieldInfo = typeof(WristbandAuthService).GetField("mWristbandApiClient", BindingFlags.NonPublic | BindingFlags.Instance);
        if (fieldInfo != null)
        {
            fieldInfo.SetValue(wristbandAuthService, _mockApiClient.Object);
        }

        return wristbandAuthService;
    }

    private void SetupDefaultLoginStateMock()
    {
        var loginState = new LoginState(
            "test-state",
            "test-verifier",
            _defaultConfig.RedirectUri!,
            string.Empty,
            null);

        _mockLoginStateHandler
            .Setup(x => x.CreateLoginState(
                It.IsAny<HttpContext>(),
                It.IsAny<string>(),
                It.IsAny<Dictionary<string, object>>()))
            .Returns(loginState);
    }
}
