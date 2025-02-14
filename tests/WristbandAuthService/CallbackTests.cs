using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

using Microsoft.AspNetCore.Http;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class CallbackTests
{
    private readonly Mock<ILoginStateHandler> _mockLoginStateHandler;
    private readonly Mock<IWristbandNetworking> _mockNetworking;
    private readonly AuthConfig _defaultConfig;

    public CallbackTests()
    {
        _defaultConfig = new AuthConfig
        {
            ClientId = "test-client",
            ClientSecret = "test-secret",
            LoginStateSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://app.example.com/callback",
            WristbandApplicationDomain = "wristband.example.com"
        };

        _mockLoginStateHandler = new Mock<ILoginStateHandler>();
        _mockNetworking = new Mock<IWristbandNetworking>();
    }

    private WristbandAuthService SetupWristbandAuthService(AuthConfig authConfig)
    {
        var wristbandAuthService = new WristbandAuthService(authConfig);

        var fieldInfo = typeof(WristbandAuthService).GetField("mWristbandNetworking", BindingFlags.NonPublic | BindingFlags.Instance);
        if (fieldInfo != null)
        {
            fieldInfo.SetValue(wristbandAuthService, _mockNetworking.Object);
        }

        var loginHandlerField = typeof(WristbandAuthService).GetField("mLoginStateHandler", BindingFlags.NonPublic | BindingFlags.Instance);
        if (loginHandlerField != null)
        {
            loginHandlerField.SetValue(wristbandAuthService, _mockLoginStateHandler.Object);
        }

        return wristbandAuthService;
    }

    [Fact]
    public async Task Callback_WithNoQueryString_ThrowsInvalidOperationException()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext("app.example.com");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.Callback(httpContext));
    }

    [Fact]
    public async Task Callback_WithInvalidState_ReturnsRedirectRequired()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "state=invalidstate&code=testcode&tenant_domain=tenant1");

        SetupLoginStateMock("differentstate", "verifier123");

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.REDIRECT_REQUIRED, result.Result);
        Assert.NotEmpty(result.RedirectUrl);
        Assert.Equal(CallbackData.Empty, result.CallbackData);
    }

    [Fact]
    public async Task Callback_WithLoginRequiredError_ReturnsRedirectRequired()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "state=teststate&error=login_required&tenant_domain=tenant1");

        SetupLoginStateMock("teststate", "verifier123");

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.REDIRECT_REQUIRED, result.Result);
        Assert.NotEmpty(result.RedirectUrl);
        Assert.Equal(CallbackData.Empty, result.CallbackData);
    }

    [Fact]
    public async Task Callback_WithNonLoginRequiredError_ThrowsWristbandError()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "state=teststate&error=invalid_request&error_description=test_error&tenant_domain=tenant1");

        SetupLoginStateMock("teststate", "verifier123");

        var ex = await Assert.ThrowsAsync<WristbandError>(() =>
            service.Callback(httpContext));
        Assert.Equal("invalid_request", ex.Error);
        Assert.Equal("test_error", ex.ErrorDescription);
    }

    [Fact]
    public async Task Callback_WithMissingCode_ThrowsArgumentException()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "state=teststate&tenant_domain=tenant1");

        SetupLoginStateMock("teststate", "verifier123");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.Callback(httpContext));
    }

    [Fact]
    public async Task Callback_WithMissingTenantDomain_ThrowsWristbandError()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "state=teststate&code=testcode");

        SetupLoginStateMock("teststate", "verifier123");

        var ex = await Assert.ThrowsAsync<WristbandError>(() =>
            service.Callback(httpContext));
        Assert.Equal("missing_tenant_domain", ex.Error);
    }

    [Fact]
    public async Task Callback_WithValidInput_ReturnsCompletedResult()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "state=teststate&code=testcode&tenant_domain=tenant1");

        SetupLoginStateMock("teststate", "verifier123");
        SetupNetworkingMock();

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.COMPLETED, result.Result);
        Assert.NotNull(result.CallbackData);
        Assert.Empty(result.RedirectUrl);
        Assert.Equal("tenant1", result.CallbackData.TenantDomainName);
        Assert.NotNull(result.CallbackData.Userinfo);
    }

    [Fact]
    public async Task Callback_WithCustomDomain_IncludesInResult()
    {
        var customDomain = "custom.tenant1.com";
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            $"state=teststate&code=testcode&tenant_domain=tenant1&tenant_custom_domain={customDomain}");

        SetupLoginStateMock("teststate", "verifier123");
        SetupNetworkingMock();

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.COMPLETED, result.Result);
        Assert.NotNull(result.CallbackData);
        Assert.Equal(customDomain, result.CallbackData.TenantCustomDomain);
    }

    [Fact]
    public async Task Callback_WhenTokenExchangeFails_ReturnsRedirectRequired()
    {
        var service = SetupWristbandAuthService(_defaultConfig);
        var httpContext = TestUtils.setupHttpContext(
            "app.example.com",
            "state=teststate&code=testcode&tenant_domain=tenant1");

        SetupLoginStateMock("teststate", "verifier123");

        _mockNetworking
            .Setup(x => x.GetTokens(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ThrowsAsync(new WristbandError("invalid_grant", "Token exchange failed"));

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.REDIRECT_REQUIRED, result.Result);
        Assert.Equal(CallbackData.Empty, result.CallbackData);
        Assert.Equal($"{_defaultConfig.LoginUrl}?tenant_domain=tenant1", result.RedirectUrl);

        _mockNetworking.Verify(x => x.GetTokens(
            "testcode",
            _defaultConfig.RedirectUri!,
            "verifier123"
        ), Times.Once);
    }

    [Fact]
    public async Task Callback_WithTenantSubdomains_ConstructsCorrectRedirectUrl()
    {
        var config = new AuthConfig
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
            "state=teststate&code=testcode");

        SetupLoginStateMock("teststate", "verifier123");

        _mockNetworking
            .Setup(x => x.GetTokens(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .ThrowsAsync(new WristbandError("invalid_grant", "Token exchange failed"));

        var result = await service.Callback(httpContext);

        Assert.Equal(CallbackResultType.REDIRECT_REQUIRED, result.Result);
        Assert.Equal(CallbackData.Empty, result.CallbackData);

        var expectedUrl = "https://tenant1.example.com/login";
        Assert.Equal(expectedUrl, result.RedirectUrl);
    }

    private void SetupLoginStateMock(string state, string codeVerifier)
    {
        var loginState = new LoginState(
            state,
            codeVerifier,
            _defaultConfig.RedirectUri!,
            string.Empty,
            null);

        _mockLoginStateHandler
            .Setup(x => x.GetAndClearLoginStateCookie(
                It.IsAny<HttpContext>(),
                It.IsAny<bool>()))
            .Returns("encryptedstate");

        _mockLoginStateHandler
            .Setup(x => x.DecryptLoginState(
                It.IsAny<string>(),
                It.IsAny<string>()))
            .Returns(loginState);
    }

    private void SetupNetworkingMock()
    {
        var tokenResponse = new TokenResponse
        {
            AccessToken = "test_access_token",
            ExpiresIn = 3600,
            IdToken = "test_id_token",
            RefreshToken = "test_refresh_token",
            Scope = "openid profile email",
            TokenType = "Bearer"
        };

        string jsonString = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            { "sub", "user123" },
            { "email", "test@example.com" }
        });
        var userInfo = new UserInfo(jsonString);

        _mockNetworking
            .Setup(x => x.GetTokens(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string>()))
            .Returns(Task.FromResult(tokenResponse));

        _mockNetworking
            .Setup(x => x.GetUserinfo(It.IsAny<string>()))
            .Returns(Task.FromResult(userInfo));
    }
}
