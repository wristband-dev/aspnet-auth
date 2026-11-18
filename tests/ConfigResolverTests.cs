using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class ConfigResolverTests
{
    private readonly Mock<IWristbandApiClient> _mockApiClient;
    private readonly WristbandAuthConfig _validConfig;

    public ConfigResolverTests()
    {
        _mockApiClient = new Mock<IWristbandApiClient>();
        _validConfig = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = true
        };
    }

    // ////////////////////////////////////
    //  CONSTRUCTOR VALIDATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_WithValidConfig_CreatesInstance()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        Assert.NotNull(resolver);
    }

    [Fact]
    public void Constructor_WithNullAuthConfig_ThrowsArgumentNullException()
    {
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        var exception = Assert.Throws<ArgumentNullException>(() => new ConfigResolver(null, _mockApiClient.Object));

        Assert.Equal("authConfig", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithNullApiClient_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(
            () => new ConfigResolver(_validConfig, null));

        Assert.Equal("wristbandApiClient", exception.ParamName);
    }

    [Theory]
    [InlineData(null, "test-client-secret", "test.wristband.dev", "The [ClientId] config must have a value.")]
    [InlineData("", "test-client-secret", "test.wristband.dev", "The [ClientId] config must have a value.")]
    [InlineData("  ", "test-client-secret", "test.wristband.dev", "The [ClientId] config must have a value.")]
    [InlineData("test-client-id", null, "test.wristband.dev", "The [ClientSecret] config must have a value.")]
    [InlineData("test-client-id", "", "test.wristband.dev", "The [ClientSecret] config must have a value.")]
    [InlineData("test-client-id", "  ", "test.wristband.dev", "The [ClientSecret] config must have a value.")]
    [InlineData("test-client-id", "test-client-secret", null, "The [WristbandApplicationVanityDomain] config must have a value.")]
    [InlineData("test-client-id", "test-client-secret", "", "The [WristbandApplicationVanityDomain] config must have a value.")]
    [InlineData("test-client-id", "test-client-secret", "  ", "The [WristbandApplicationVanityDomain] config must have a value.")]
    public void Constructor_WithInvalidRequiredConfigs_ThrowsArgumentException(
        string clientId, string clientSecret, string domain, string expectedMessage)
    {
        var config = new WristbandAuthConfig
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            WristbandApplicationVanityDomain = domain,
            AutoConfigureEnabled = true
        };

        var exception = Assert.Throws<ArgumentException>(
            () => new ConfigResolver(config, _mockApiClient.Object));

        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void Constructor_WithShortLoginStateSecret_ThrowsArgumentException()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginStateSecret = "short", // Less than 32 characters
            AutoConfigureEnabled = true
        };

        var exception = Assert.Throws<ArgumentException>(
            () => new ConfigResolver(config, _mockApiClient.Object));

        Assert.Equal("The [LoginStateSecret] config must have a value of at least 32 characters.", exception.Message);
    }

    [Fact]
    public void Constructor_WithValidLoginStateSecret_DoesNotThrow()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginStateSecret = "this-is-a-32-character-secret123", // Exactly 32 characters
            AutoConfigureEnabled = true
        };

        var resolver = new ConfigResolver(config, _mockApiClient.Object);
        Assert.NotNull(resolver);
    }

    [Fact]
    public void Constructor_WithNullLoginStateSecret_DoesNotThrow()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginStateSecret = null,
            AutoConfigureEnabled = true
        };

        var resolver = new ConfigResolver(config, _mockApiClient.Object);
        Assert.NotNull(resolver);
    }

    [Fact]
    public void Constructor_WithNegativeTokenExpirationBuffer_ThrowsArgumentException()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            TokenExpirationBuffer = -1,
            AutoConfigureEnabled = true
        };

        var exception = Assert.Throws<ArgumentException>(
            () => new ConfigResolver(config, _mockApiClient.Object));

        Assert.Equal("The [TokenExpirationBuffer] config must be greater than or equal to 0.", exception.Message);
    }

    [Fact]
    public void Constructor_WithZeroTokenExpirationBuffer_DoesNotThrow()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            TokenExpirationBuffer = 0,
            AutoConfigureEnabled = true
        };

        var resolver = new ConfigResolver(config, _mockApiClient.Object);
        Assert.NotNull(resolver);
    }

    [Fact]
    public void Constructor_WithAutoConfigureFalseAndMissingLoginUrl_ThrowsArgumentException()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            RedirectUri = "https://app.example.com/callback"
        };

        var exception = Assert.Throws<ArgumentException>(
            () => new ConfigResolver(config, _mockApiClient.Object));

        Assert.Equal("The [LoginUrl] config must have a value when auto-configure is disabled.", exception.Message);
    }

    [Fact]
    public void Constructor_WithAutoConfigureFalseAndMissingRedirectUri_ThrowsArgumentException()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://app.example.com/login"
        };

        var exception = Assert.Throws<ArgumentException>(
            () => new ConfigResolver(config, _mockApiClient.Object));

        Assert.Equal("The [RedirectUri] config must have a value when auto-configure is disabled.", exception.Message);
    }

    // ////////////////////////////////////
    //  SIMPLE GETTER TESTS
    // ////////////////////////////////////

    [Fact]
    public void GetClientId_ReturnsConfigValue()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = resolver.GetClientId();

        Assert.Equal("test-client-id", result);
    }

    [Fact]
    public void GetClientSecret_ReturnsConfigValue()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = resolver.GetClientSecret();

        Assert.Equal("test-client-secret", result);
    }

    [Fact]
    public void GetLoginStateSecret_WithoutValue_ReturnsClientSecret()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = resolver.GetLoginStateSecret();

        Assert.Equal("test-client-secret", result);
    }

    [Fact]
    public void GetLoginStateSecret_WithValue_ReturnsConfigValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginStateSecret = "custom-login-state-secret-32-chars",
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = resolver.GetLoginStateSecret();

        Assert.Equal("custom-login-state-secret-32-chars", result);
    }

    [Fact]
    public void GetWristbandApplicationVanityDomain_ReturnsConfigValue()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = resolver.GetWristbandApplicationVanityDomain();

        Assert.Equal("test.wristband.dev", result);
    }

    [Fact]
    public void GetDangerouslyDisableSecureCookies_WithoutValue_ReturnsFalse()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = resolver.GetDangerouslyDisableSecureCookies();

        Assert.False(result);
    }

    [Fact]
    public void GetDangerouslyDisableSecureCookies_WithValue_ReturnsConfigValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            DangerouslyDisableSecureCookies = true,
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = resolver.GetDangerouslyDisableSecureCookies();

        Assert.True(result);
    }

    [Fact]
    public void GetScopes_WithoutValue_ReturnsDefaultScopes()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = resolver.GetScopes();

        Assert.Equal(new List<string> { "openid", "offline_access", "email" }, result);
    }

    [Fact]
    public void GetScopes_WithValue_ReturnsConfigValue()
    {
        var customScopes = new List<string> { "openid", "profile", "custom" };
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            Scopes = customScopes,
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = resolver.GetScopes();

        Assert.Equal(customScopes, result);
    }

    [Fact]
    public void GetScopes_WithEmptyList_ReturnsDefaultScopes()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            Scopes = new List<string>(),
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = resolver.GetScopes();

        Assert.Equal(new List<string> { "openid", "offline_access", "email" }, result);
    }

    [Fact]
    public void GetAutoConfigureEnabled_WithoutValue_ReturnsTrue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = null
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = resolver.GetAutoConfigureEnabled();

        Assert.True(result);
    }

    [Fact]
    public void GetAutoConfigureEnabled_WithValue_ReturnsConfigValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = resolver.GetAutoConfigureEnabled();

        Assert.False(result);
    }

    [Fact]
    public void GetTokenExpirationBuffer_WithoutValue_ReturnsDefault()
    {
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = resolver.GetTokenExpirationBuffer();

        Assert.Equal(60, result);
    }

    [Fact]
    public void GetTokenExpirationBuffer_WithValue_ReturnsConfigValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            TokenExpirationBuffer = 120,
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = resolver.GetTokenExpirationBuffer();

        Assert.Equal(120, result);
    }

    // ////////////////////////////////////
    //  ASYNC GETTER TESTS - MANUAL CONFIG PRECEDENCE
    // ////////////////////////////////////

    [Fact]
    public async Task GetCustomApplicationLoginPageUrl_WithManualConfig_ReturnsManualValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            CustomApplicationLoginPageUrl = "https://manual.com/custom",
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetCustomApplicationLoginPageUrl();

        Assert.Equal("https://manual.com/custom", result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Fact]
    public async Task GetIsApplicationCustomDomainActive_WithManualConfig_ReturnsManualValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            IsApplicationCustomDomainActive = true,
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetIsApplicationCustomDomainActive();

        Assert.True(result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Fact]
    public async Task GetLoginUrl_WithManualConfig_ReturnsManualValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginUrl = "https://manual-login.example.com",
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetLoginUrl();

        Assert.Equal("https://manual-login.example.com", result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Fact]
    public async Task GetRedirectUri_WithManualConfig_ReturnsManualValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            RedirectUri = "https://manual-callback.example.com",
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetRedirectUri();

        Assert.Equal("https://manual-callback.example.com", result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Fact]
    public async Task GetParseTenantFromRootDomain_WithManualConfig_ReturnsManualValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginUrl = "https://{tenant_name}.manual.example.com/login",
            RedirectUri = "https://{tenant_name}.manual.example.com/callback",
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetParseTenantFromRootDomain();

        Assert.Equal("manual.example.com", result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    // ////////////////////////////////////
    //  ASYNC GETTER TESTS - AUTO CONFIG FALLBACK
    // ////////////////////////////////////

    [Fact]
    public async Task GetCustomApplicationLoginPageUrl_WithAutoConfigureAndSdkValue_ReturnsSdkValue()
    {
        var sdkConfig = new SdkConfiguration
        {
            CustomApplicationLoginPageUrl = "https://sdk-login.example.com",
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetCustomApplicationLoginPageUrl();

        Assert.Equal("https://sdk-login.example.com", result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task GetCustomApplicationLoginPageUrl_WithAutoConfigureAndNoSdkValue_ReturnsEmptyString()
    {
        var sdkConfig = new SdkConfiguration
        {
            CustomApplicationLoginPageUrl = null,
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetCustomApplicationLoginPageUrl();

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public async Task GetIsApplicationCustomDomainActive_WithAutoConfigureAndSdkValue_ReturnsSdkValue()
    {
        var sdkConfig = new SdkConfiguration
        {
            IsApplicationCustomDomainActive = true,
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetIsApplicationCustomDomainActive();

        Assert.True(result);
    }

    [Fact]
    public async Task GetLoginUrl_WithAutoConfigureAndSdkValue_ReturnsSdkValue()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk-login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetLoginUrl();

        Assert.Equal("https://sdk-login.example.com", result);
    }

    [Fact]
    public async Task GetRedirectUri_WithAutoConfigureAndSdkValue_ReturnsSdkValue()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://sdk-callback.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetRedirectUri();

        Assert.Equal("https://sdk-callback.example.com", result);
    }

    [Fact]
    public async Task GetParseTenantFromRootDomain_WithAutoConfigureAndSdkValue_ReturnsSdkValue()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://{tenant_name}.sdk.example.com/login",
            RedirectUri = "https://{tenant_name}.sdk.example.com/callback",
            LoginUrlTenantDomainSuffix = "sdk.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetParseTenantFromRootDomain();

        Assert.Equal("sdk.example.com", result);
    }

    [Fact]
    public async Task GetParseTenantFromRootDomain_WithAutoConfigureAndNoSdkValue_ReturnsEmptyString()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com",
            LoginUrlTenantDomainSuffix = null
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetParseTenantFromRootDomain();

        Assert.Equal(string.Empty, result);
    }

    // ////////////////////////////////////
    //  AUTO CONFIG DISABLED FALLBACK TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task GetCustomApplicationLoginPageUrl_WithAutoConfigureDisabled_ReturnsEmptyString()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetCustomApplicationLoginPageUrl();

        Assert.Equal(string.Empty, result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Fact]
    public async Task GetIsApplicationCustomDomainActive_WithAutoConfigureDisabled_ReturnsFalse()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetIsApplicationCustomDomainActive();

        Assert.False(result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Fact]
    public async Task GetParseTenantFromRootDomain_WithAutoConfigureDisabled_ReturnsEmptyString()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetParseTenantFromRootDomain();

        Assert.Equal(string.Empty, result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    // ////////////////////////////////////
    //  PRELOAD CONFIG TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task PreloadConfig_WithAutoConfigureEnabled_LoadsConfiguration()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        await resolver.PreloadConfig();

        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task PreloadConfig_WithAutoConfigureDisabled_ThrowsWristbandError()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.PreloadConfig());

        Assert.Equal("config_error", exception.Error);
        Assert.Contains("Cannot preload configs when AutoConfigureEnabled is false", exception.ErrorDescription);
    }

    // ////////////////////////////////////
    //  SDK CONFIGURATION CACHING TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task SdkConfigurationCaching_MultipleCallsOnlyFetchOnce()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com",
            CustomApplicationLoginPageUrl = "https://custom.example.com",
            IsApplicationCustomDomainActive = true
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        // Create config without IsApplicationCustomDomainActive set
        var testConfig = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = true
            // Don't set IsApplicationCustomDomainActive - let it use SDK config
        };
        var resolver = new ConfigResolver(testConfig, _mockApiClient.Object);

        // Multiple calls to different getters
        var loginUrl = await resolver.GetLoginUrl();
        var redirectUri = await resolver.GetRedirectUri();
        var customUrl = await resolver.GetCustomApplicationLoginPageUrl();
        var customDomain = await resolver.GetIsApplicationCustomDomainActive();

        Assert.Equal("https://login.example.com", loginUrl);
        Assert.Equal("https://callback.example.com", redirectUri);
        Assert.Equal("https://custom.example.com", customUrl);
        Assert.True(customDomain);

        // Should only have called the API once due to caching
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once);
    }

    // ////////////////////////////////////
    //  SDK CONFIGURATION VALIDATION TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task GetLoginUrl_WithSdkConfigMissingLoginUrl_ThrowsWristbandError()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "", // Missing required field
            RedirectUri = "https://callback.example.com"
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.GetLoginUrl());

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Contains("SDK configuration response missing required field: LoginUrl", exception.ErrorDescription);
    }

    [Fact]
    public async Task GetRedirectUri_WithSdkConfigMissingRedirectUri_ThrowsWristbandError()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = "" // Missing required field
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.GetRedirectUri());

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Contains("The [RedirectUri] could not be resolved. Provide it explicitly in your SDK config or ensure your Wristband OAuth2 Client has a single redirect URI configured.", exception.ErrorDescription);
    }

    [Fact]
    public async Task GetRedirectUri_WithNullSdkRedirectUriAndManualOverride_ReturnsManualValue()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = null // SDK returns null (multiple redirect URIs registered)
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            RedirectUri = "https://manual-callback.example.com",
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var result = await resolver.GetRedirectUri();

        Assert.Equal("https://manual-callback.example.com", result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Fact]
    public async Task GetRedirectUri_WithEmptySdkRedirectUri_ThrowsWristbandError()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = "" // Empty string also triggers error
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.GetRedirectUri());

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Contains("The [RedirectUri] could not be resolved", exception.ErrorDescription);
        Assert.Contains("Provide it explicitly in your SDK config or ensure your Wristband OAuth2 Client has a single redirect URI configured.", exception.ErrorDescription);
    }

    [Fact]
    public async Task GetRedirectUri_WithNullSdkRedirectUri_ThrowsWristbandError()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = null // SDK returns null (multiple redirect URIs registered)
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.GetRedirectUri());

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Contains("The [RedirectUri] could not be resolved. Provide it explicitly in your SDK config or ensure your Wristband OAuth2 Client has a single redirect URI configured.", exception.ErrorDescription);
    }

    // ////////////////////////////////////
    //  SDK CONFIGURATION FETCH TESTS
    // ////////////////////////////////////

    // Retrying transient failures is handled one layer down by the API client, so the resolver makes
    // a single call per fetch. Retrying here as well would compound the two policies into far more
    // attempts than intended.
    [Fact]
    public async Task SdkConfigurationFetch_DelegatesRetryToApiClient_MakesSingleCall()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://login.example.com",
            RedirectUri = "https://callback.example.com"
        };

        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var result = await resolver.GetLoginUrl();

        Assert.Equal("https://login.example.com", result);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once());
    }

    [Fact]
    public async Task SdkConfigurationFetch_WhenApiClientFails_ThrowsWristbandError()
    {
        _mockApiClient.Setup(x => x.GetSdkConfiguration())
            .ThrowsAsync(new Exception("Persistent network error"));

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.GetLoginUrl());

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Contains("Failed to fetch SDK configuration", exception.ErrorDescription);
        Assert.Contains("Persistent network error", exception.ErrorDescription);
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once());
    }

    // ////////////////////////////////////
    //  DYNAMIC CONFIGURATION VALIDATION TESTS
    // ////////////////////////////////////

    // ////////////////////////////////////
    //  EDGE CASES AND INTEGRATION TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task MixedManualAndAutoConfig_UsesCorrectPrecedence()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
            CustomApplicationLoginPageUrl = null,
            IsApplicationCustomDomainActive = false,
            LoginUrlTenantDomainSuffix = null
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginUrl = "https://manual.example.com/login", // Manual override
            // RedirectUri will come from auto-config
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var loginUrl = await resolver.GetLoginUrl();
        var redirectUri = await resolver.GetRedirectUri();
        var customUrl = await resolver.GetCustomApplicationLoginPageUrl();

        Assert.Equal("https://manual.example.com/login", loginUrl); // Manual
        Assert.Equal("https://sdk.example.com/callback", redirectUri); // Auto-config
        Assert.Equal(string.Empty, customUrl); // Auto-config empty

        // Should only call SDK once despite multiple getters
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task BooleanHandling_ForIsApplicationCustomDomainActive_HandlesAllCases()
    {
        // Test explicit False
        var config1 = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            IsApplicationCustomDomainActive = false,
            AutoConfigureEnabled = true
        };
        var resolver1 = new ConfigResolver(config1, _mockApiClient.Object);
        var result1 = await resolver1.GetIsApplicationCustomDomainActive();
        Assert.False(result1);

        // Test explicit True
        var config2 = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            IsApplicationCustomDomainActive = true,
            AutoConfigureEnabled = true
        };
        var resolver2 = new ConfigResolver(config2, _mockApiClient.Object);
        var result2 = await resolver2.GetIsApplicationCustomDomainActive();
        Assert.True(result2);

        // Test null with auto-config
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
            IsApplicationCustomDomainActive = false
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var config3 = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            IsApplicationCustomDomainActive = null,
            AutoConfigureEnabled = true
        };
        var resolver3 = new ConfigResolver(config3, _mockApiClient.Object);
        var result3 = await resolver3.GetIsApplicationCustomDomainActive();
        Assert.False(result3);
    }

    [Fact]
    public async Task EmptyStringValues_AreHandledCorrectly()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
            CustomApplicationLoginPageUrl = null,
            IsApplicationCustomDomainActive = true
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            CustomApplicationLoginPageUrl = "",
            AutoConfigureEnabled = true
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var customUrl = await resolver.GetCustomApplicationLoginPageUrl();
        var parseTenant = await resolver.GetParseTenantFromRootDomain();

        Assert.Equal("", customUrl);
        Assert.Equal("", parseTenant);
    }

    [Fact]
    public async Task ManualConfigTakesPrecedenceInValidation()
    {
        // Manual config has correct tenant name token
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginUrl = "https://{tenant_name}.manual.com/login",
            AutoConfigureEnabled = true
        };

        // SDK config would fail validation if used
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login", // No tenant token
            RedirectUri = "https://{tenant_name}.sdk.com/callback",
            IsApplicationCustomDomainActive = true
        };
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(sdkConfig);

        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        // Should not raise validation error because manual login_url is used
        var result = await resolver.GetLoginUrl();
        Assert.Equal("https://{tenant_name}.manual.com/login", result);
    }

    [Fact]
    public async Task ErrorPreservesOriginalMessage()
    {
        var originalError = new Exception("Network connection failed");
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ThrowsAsync(originalError);

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.GetLoginUrl());

        Assert.Contains("Network connection failed", exception.ErrorDescription);
    }

    [Fact]
    public async Task ErrorAllowsRetryAfterFailure()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback"
        };

        _mockApiClient.SetupSequence(x => x.GetSdkConfiguration())
            .ThrowsAsync(new Exception("First error"))
            .ReturnsAsync(sdkConfig); // Success on the next fetch

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        // A failed fetch is not cached, so the error surfaces.
        var firstException = await Assert.ThrowsAsync<WristbandError>(
            () => resolver.GetLoginUrl());
        Assert.Contains("Failed to fetch SDK configuration", firstException.ErrorDescription);

        // Second attempt should succeed (new cache attempt)
        var result = await resolver.GetRedirectUri();
        Assert.Equal("https://sdk.example.com/callback", result);

        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Exactly(2));
    }

    // ////////////////////////////////////
    //  THREAD SAFETY TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task ThreadSafety_MultipleThreadsCallGetters_OnlyFetchOnce()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
            CustomApplicationLoginPageUrl = "https://custom.example.com",
            IsApplicationCustomDomainActive = true
        };

        _mockApiClient.Setup(x => x.GetSdkConfiguration())
            .Returns(async () =>
            {
                // Add small delay to simulate network request
                await Task.Delay(50);
                return sdkConfig;
            });

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var loginUrlTask = Task.Run(async () => await resolver.GetLoginUrl());
        var redirectUriTask = Task.Run(async () => await resolver.GetRedirectUri());
        var customUrlTask = Task.Run(async () => await resolver.GetCustomApplicationLoginPageUrl());
        var customDomainTask = Task.Run(async () => await resolver.GetIsApplicationCustomDomainActive());

        // Wait for all tasks to complete
        await Task.WhenAll(loginUrlTask, redirectUriTask, customUrlTask, customDomainTask);

        // Access individual results after completion
        Assert.Equal("https://sdk.example.com/login", await loginUrlTask);
        Assert.Equal("https://sdk.example.com/callback", await redirectUriTask);
        Assert.Equal("https://custom.example.com", await customUrlTask);
        Assert.True(await customDomainTask);

        // Should only have called the API once due to thread safety and caching
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task ThreadSafety_ConcurrentPreloadAndGetRequests_WorksCorrectly()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
            IsApplicationCustomDomainActive = false
        };

        _mockApiClient.Setup(x => x.GetSdkConfiguration())
            .Returns(async () =>
            {
                await Task.Delay(100); // Simulate network delay
                return sdkConfig;
            });

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        var tasks = new List<Task>
        {
            Task.Run(async () => await resolver.PreloadConfig()),
            Task.Run(async () => await resolver.GetLoginUrl()),
            Task.Run(async () => await resolver.GetRedirectUri()),
            Task.Run(async () => await resolver.GetIsApplicationCustomDomainActive())
        };

        await Task.WhenAll(tasks);

        // Should only make one API call despite multiple concurrent requests
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task ThreadSafety_ErrorRecoveryAcrossThreads_WorksCorrectly()
    {
        var sdkConfig = new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback"
        };

        var callCount = 0;
        _mockApiClient.Setup(x => x.GetSdkConfiguration())
            .Returns(() =>
            {
                callCount++;
                if (callCount <= 1)
                {
                    throw new Exception($"Error {callCount}");
                }
                return Task.FromResult(sdkConfig);
            });

        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        // First attempt should fail
        await Assert.ThrowsAsync<WristbandError>(() => resolver.GetLoginUrl());
        Assert.Equal(1, callCount);

        // Concurrent requests after failure should succeed
        var loginUrlTask = Task.Run(async () => await resolver.GetLoginUrl());
        var redirectUriTask = Task.Run(async () => await resolver.GetRedirectUri());

        var results = await Task.WhenAll(loginUrlTask, redirectUriTask);

        Assert.Equal("https://sdk.example.com/login", results[0]);
        Assert.Equal("https://sdk.example.com/callback", results[1]);
        Assert.Equal(2, callCount); // One more successful call
    }

    // ////////////////////////////////////
    //  TENANT PLACEHOLDER VALIDATION TESTS
    // ////////////////////////////////////

    private static WristbandAuthConfig StrictConfig(string loginUrl, string redirectUri)
    {
        return new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = loginUrl,
            RedirectUri = redirectUri,
        };
    }

    [Theory]
    [InlineData("https://{tenant_name}.test.com/login", "https://test.com/callback", "The [RedirectUri] must contain the \"{tenant_name}\" placeholder when the [LoginUrl] contains it.")]
    [InlineData("https://test.com/login", "https://{tenant_name}.test.com/callback", "The [RedirectUri] cannot contain the \"{tenant_name}\" placeholder when the [LoginUrl] does not contain it.")]
    [InlineData("https://app.{tenant_name}.test.com/login", "https://{tenant_name}.test.com/callback", "The [LoginUrl] can only contain the \"{tenant_name}\" placeholder once, as the leftmost part of its hostname.")]
    [InlineData("https://{tenant_name}.test.com/{tenant_name}/login", "https://{tenant_name}.test.com/callback", "The [LoginUrl] can only contain the \"{tenant_name}\" placeholder once, as the leftmost part of its hostname.")]
    [InlineData("https://{tenant_name}.test.com/login", "https://test.com/{tenant_name}/callback", "The [RedirectUri] can only contain the \"{tenant_name}\" placeholder once, as the leftmost part of its hostname.")]
    [InlineData("https://{tenant_domain}.test.com/login", "https://{tenant_name}.test.com/callback", "The [RedirectUri] cannot contain the \"{tenant_name}\" placeholder when the [LoginUrl] does not contain it.")]
    public void Constructor_WithInvalidTenantPlaceholders_ThrowsArgumentException(string loginUrl, string redirectUri, string expectedMessage)
    {
        var exception = Assert.Throws<ArgumentException>(() => new ConfigResolver(StrictConfig(loginUrl, redirectUri), _mockApiClient.Object));
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Theory]
    [InlineData("https://{tenant_name}.test.com/login", "https://{tenant_name}.test.com/callback")]
    [InlineData("http://{tenant_name}.localhost:6001/login", "http://{tenant_name}.localhost:6001/callback")]
    [InlineData("https://test.com/login", "https://test.com/callback")]
    public void Constructor_WithValidTenantPlaceholders_Succeeds(string loginUrl, string redirectUri)
    {
        var resolver = new ConfigResolver(StrictConfig(loginUrl, redirectUri), _mockApiClient.Object);
        Assert.NotNull(resolver);
    }

    [Fact]
    public void Constructor_WithPartialUrlConfigs_ValidatesPlaceholderPosition()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginUrl = "https://app.{tenant_name}.test.com/login",
        };

        var exception = Assert.Throws<ArgumentException>(() => new ConfigResolver(config, _mockApiClient.Object));
        Assert.Contains("The [LoginUrl] can only contain", exception.Message);
    }

    [Fact]
    public void Constructor_WithOnlyManualLoginUrl_DefersPlaceholderComparison()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginUrl = "https://{tenant_name}.test.com/login",
        };

        Assert.NotNull(new ConfigResolver(config, _mockApiClient.Object));
    }

    [Fact]
    public async Task DynamicValidation_WithManualLoginUrlPlaceholderButNoResolvedRedirectUriPlaceholder_ThrowsWristbandError()
    {
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
        });
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            LoginUrl = "https://{tenant_name}.test.com/login",
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        var exception = await Assert.ThrowsAsync<WristbandError>(() => resolver.GetRedirectUri());

        Assert.Equal("config_validation_error", exception.Error);
        Assert.Contains("The resolved [RedirectUri] must contain the", exception.ErrorDescription);
    }

    [Fact]
    public async Task DynamicValidation_WithSdkUrlsOnly_TrustsPlaceholdersAsIs()
    {
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(new SdkConfiguration
        {
            LoginUrl = "https://{tenant_name}.sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
        });
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        Assert.Equal("https://{tenant_name}.sdk.example.com/login", await resolver.GetLoginUrl());
    }

    // ////////////////////////////////////
    //  DERIVED AND APP-LEVEL CONFIG TESTS
    // ////////////////////////////////////

    [Theory]
    [InlineData("https://{tenant_name}.myapp.com/auth/login", "myapp.com", "https://myapp.com/auth/login")]
    [InlineData("http://{tenant_name}.localhost:6001/auth/login", "localhost", "http://localhost:6001/auth/login")]
    [InlineData("https://myapp.com/auth/login", "", "")]
    public async Task RootDomainAndFallbackLoginUrl_AreDerivedFromManualLoginUrl(string loginUrl, string expectedRootDomain, string expectedFallbackLoginUrl)
    {
        var resolver = new ConfigResolver(StrictConfig(loginUrl, loginUrl.Replace("/auth/login", "/auth/callback")), _mockApiClient.Object);

        Assert.Equal(expectedRootDomain, await resolver.GetParseTenantFromRootDomain());
        Assert.Equal(expectedFallbackLoginUrl, await resolver.GetFallbackLoginUrl());
    }

    [Fact]
    public async Task RootDomainAndFallbackLoginUrl_ComeFromSdkConfigWithoutManualLoginUrl()
    {
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(new SdkConfiguration
        {
            LoginUrl = "https://{tenant_name}.sdk.example.com/login",
            RedirectUri = "https://{tenant_name}.sdk.example.com/callback",
            LoginUrlTenantDomainSuffix = "sdk.example.com",
            FallbackLoginUrl = "https://sdk.example.com/login",
        });
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        Assert.Equal("sdk.example.com", await resolver.GetParseTenantFromRootDomain());
        Assert.Equal("https://sdk.example.com/login", await resolver.GetFallbackLoginUrl());
    }

    [Fact]
    public async Task GetApplicationAuthorizationRequestsEnabled_WithAutoConfigureDisabled_DefaultsToTrue()
    {
        var resolver = new ConfigResolver(StrictConfig("https://test.com/login", "https://test.com/callback"), _mockApiClient.Object);
        Assert.True(await resolver.GetApplicationAuthorizationRequestsEnabled());
    }

    [Fact]
    public async Task GetApplicationAuthorizationRequestsEnabled_WithManualConfig_ReturnsManualValue()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret",
            WristbandApplicationVanityDomain = "test.wristband.dev",
            ApplicationAuthorizationRequestsEnabled = false,
        };
        var resolver = new ConfigResolver(config, _mockApiClient.Object);

        Assert.False(await resolver.GetApplicationAuthorizationRequestsEnabled());
        _mockApiClient.Verify(x => x.GetSdkConfiguration(), Times.Never);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GetApplicationAuthorizationRequestsEnabled_WithAutoConfigure_ReturnsSdkValue(bool sdkValue)
    {
        _mockApiClient.Setup(x => x.GetSdkConfiguration()).ReturnsAsync(new SdkConfiguration
        {
            LoginUrl = "https://sdk.example.com/login",
            RedirectUri = "https://sdk.example.com/callback",
            ApplicationAuthorizationRequestsEnabled = sdkValue,
        });
        var resolver = new ConfigResolver(_validConfig, _mockApiClient.Object);

        Assert.Equal(sdkValue, await resolver.GetApplicationAuthorizationRequestsEnabled());
    }
}
