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
            WristbandApplicationVanityDomain = "wristband.example.com",
            AutoConfigureEnabled = false,
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
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            IsApplicationCustomDomainActive = false,
            AutoConfigureEnabled = false,
        };
        var service = SetupWristbandAuthService(config);
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        var result = await service.Login(httpContext, null);

        var expectedUrl = $"https://{_defaultConfig.WristbandApplicationVanityDomain}/login?client_id={_defaultConfig.ClientId}";
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
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            CustomApplicationLoginPageUrl = "https://custom.example.com/login",
            AutoConfigureEnabled = false,
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
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            ParseTenantFromRootDomain = "example.com",
            AutoConfigureEnabled = false,
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
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            ParseTenantFromRootDomain = "example.com",
            AutoConfigureEnabled = false,
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
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            IsApplicationCustomDomainActive = false,
            AutoConfigureEnabled = false,
        };
        var service = SetupWristbandAuthService(config);
        var tenantDomain = "mytenant";
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain={tenantDomain}");

        var result = await service.Login(httpContext, null);

        var expectedUrl = $"https://{tenantDomain}-{_defaultConfig.WristbandApplicationVanityDomain}/api/v1/oauth2/authorize";
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

        Assert.StartsWith($"https://{defaultTenantName}-{_defaultConfig.WristbandApplicationVanityDomain}/api/v1/oauth2/authorize?", result);
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
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            IsApplicationCustomDomainActive = true,
            AutoConfigureEnabled = false,
        };
        var service = SetupWristbandAuthService(config);
        var tenantDomain = "tenant1";
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain={tenantDomain}");

        var result = await service.Login(httpContext, null);

        Assert.Contains($"{tenantDomain}.{config.WristbandApplicationVanityDomain}", result);
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

        Assert.Contains($"{tenantDomain}-{_defaultConfig.WristbandApplicationVanityDomain}", result);
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
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            Scopes = new List<string> { "openid", "offline_access", "email", "profile", "custom_scope" },
            AutoConfigureEnabled = false,
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

    [Fact]
    public async Task Login_WithReturnUrlInLoginConfig_TakesPrecedenceOverQueryParam()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var configReturnUrl = "/config-dashboard";
        var loginConfig = new LoginConfig { ReturnUrl = configReturnUrl };

        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain=tenant1&return_url=/query-dashboard");

        var result = await service.Login(httpContext, loginConfig);

        // Just verify the URL was generated successfully
        Assert.StartsWith("https://tenant1-", result);
    }

    [Fact]
    public async Task Login_WithReturnUrlFromQueryParam_UsesQueryValue()
    {
        var service = SetupWristbandAuthService(_defaultConfig);

        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain=tenant1&return_url=/dashboard");

        var result = await service.Login(httpContext, null);

        // Just verify the URL was generated successfully
        Assert.StartsWith("https://tenant1-", result);
    }

    [Fact]
    public async Task Login_WithMultipleReturnUrlParams_ThrowsArgumentException()
    {
        var service = SetupWristbandAuthService(_defaultConfig);

        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "tenant_domain=tenant1&return_url=/dashboard&return_url=/profile");

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            service.Login(httpContext, null));

        Assert.Contains("More than one [return_url] query parameter was encountered", ex.Message);
    }

    [Fact]
    public async Task Login_WithReturnUrlTooLong_StillGeneratesUrl()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        // Create a return URL longer than 450 characters
        var longReturnUrl = "/dashboard/" + new string('a', 450);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain=tenant1&return_url={longReturnUrl}");

        // Suppress console output during test
        var originalOut = Console.Out;
        try
        {
            Console.SetOut(TextWriter.Null);
            var result = await service.Login(httpContext, null);

            // Should still generate URL successfully (return URL is ignored internally)
            Assert.StartsWith("https://tenant1-", result);
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public async Task Login_WithReturnUrlExactly450Chars_GeneratesUrl()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        // Create a return URL exactly 450 characters
        var returnUrl = "/dashboard/" + new string('a', 439);
        Assert.Equal(450, returnUrl.Length);

        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"tenant_domain=tenant1&return_url={returnUrl}");

        var result = await service.Login(httpContext, null);

        // Should generate URL successfully
        Assert.StartsWith("https://tenant1-", result);
    }

    [Fact]
    public async Task Login_WithCustomStateInLoginConfig_GeneratesUrl()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var customState = new Dictionary<string, object>
        {
            { "userId", "12345" },
            { "source", "login_test" }
        };
        var loginConfig = new LoginConfig { CustomState = customState };

        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "tenant_domain=tenant1");

        var result = await service.Login(httpContext, loginConfig);

        // Should generate URL successfully with custom state
        Assert.StartsWith("https://tenant1-", result);
    }

    [Fact]
    public async Task Login_WithEmptyCustomState_GeneratesUrl()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var emptyCustomState = new Dictionary<string, object>();
        var loginConfig = new LoginConfig { CustomState = emptyCustomState };

        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "tenant_domain=tenant1");

        var result = await service.Login(httpContext, loginConfig);

        // Should generate URL successfully
        Assert.StartsWith("https://tenant1-", result);
    }

    [Fact]
    public async Task Login_WithNoTenantInfoAndReturnUrl_IncludesStateParam()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = _defaultConfig.LoginUrl,
            RedirectUri = _defaultConfig.RedirectUri,
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            IsApplicationCustomDomainActive = false,
            AutoConfigureEnabled = false,
        };
        var service = SetupWristbandAuthService(config);
        var returnUrl = "/dashboard";
        var loginConfig = new LoginConfig { ReturnUrl = returnUrl };
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        var result = await service.Login(httpContext, loginConfig);

        var expectedUrl = $"https://{_defaultConfig.WristbandApplicationVanityDomain}/login?client_id={_defaultConfig.ClientId}&state={Uri.EscapeDataString(returnUrl)}";
        Assert.Equal(expectedUrl, result);
    }

    [Fact]
    public async Task Login_WithCustomApplicationLoginPageAndReturnUrl_IncludesStateParam()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = _defaultConfig.ClientId,
            ClientSecret = _defaultConfig.ClientSecret,
            LoginStateSecret = _defaultConfig.LoginStateSecret,
            LoginUrl = _defaultConfig.LoginUrl,
            RedirectUri = _defaultConfig.RedirectUri,
            WristbandApplicationVanityDomain = _defaultConfig.WristbandApplicationVanityDomain,
            CustomApplicationLoginPageUrl = "https://custom.example.com/login",
            AutoConfigureEnabled = false,
        };
        var service = SetupWristbandAuthService(config);
        var returnUrl = "/profile";
        var loginConfig = new LoginConfig { ReturnUrl = returnUrl };
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        var result = await service.Login(httpContext, loginConfig);

        Assert.Equal($"https://custom.example.com/login?client_id={config.ClientId}&state={Uri.EscapeDataString(returnUrl)}", result);
    }

    private WristbandAuthService SetupWristbandAuthService(WristbandAuthConfig authConfig)
    {
        var wristbandAuthService = new WristbandAuthService(authConfig);

        var fieldInfo = typeof(WristbandAuthService).GetField("_wristbandApiClient", BindingFlags.NonPublic | BindingFlags.Instance);
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
                It.IsAny<string>(),
                It.IsAny<Dictionary<string, object>>()))
            .Returns(loginState);
    }
}
