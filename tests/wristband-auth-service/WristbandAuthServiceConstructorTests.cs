using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandAuthServiceConstructorTests
{
    private WristbandAuthConfig CreateValidConfig()
    {
        return new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = false, // Disable auto-config for simpler testing
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback"
        };
    }

    [Fact]
    public void DefaultConstructor_ShouldCreateService_WithValidConfig()
    {
        var config = CreateValidConfig();
        var service = new WristbandAuthService(config);

        Assert.NotNull(service);
    }

    [Fact]
    public void ParameterizedConstructor_ShouldAcceptNullHttpClientFactory()
    {
        var config = CreateValidConfig();
        var service = new WristbandAuthService(config, null);

        Assert.NotNull(service);
    }

    [Fact]
    public void ParameterizedConstructor_ShouldAcceptCustomHttpClientFactory()
    {
        var config = CreateValidConfig();
        var mockFactory = new Mock<IHttpClientFactory>();
        var service = new WristbandAuthService(config, mockFactory.Object);

        Assert.NotNull(service);
    }

    // ////////////////////////////////////
    //  VALIDATION TESTS (via ConfigResolver)
    // ////////////////////////////////////

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenClientIdIsEmpty()
    {
        var config = CreateValidConfig();
        config.ClientId = "";

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("ClientId", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenClientIdIsNull()
    {
        var config = CreateValidConfig();
        config.ClientId = null;

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("ClientId", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenClientSecretIsEmpty()
    {
        var config = CreateValidConfig();
        config.ClientSecret = "";

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("ClientSecret", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenClientSecretIsNull()
    {
        var config = CreateValidConfig();
        config.ClientSecret = null;

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("ClientSecret", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenLoginStateSecretTooShort()
    {
        var config = CreateValidConfig();
        config.LoginStateSecret = "short"; // Less than 32 characters

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("LoginStateSecret", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldAllowNullLoginStateSecret()
    {
        var config = CreateValidConfig();
        config.LoginStateSecret = null; // Should fallback to ClientSecret

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenVanityDomainIsEmpty()
    {
        var config = CreateValidConfig();
        config.WristbandApplicationVanityDomain = "";

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("WristbandApplicationVanityDomain", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenVanityDomainIsNull()
    {
        var config = CreateValidConfig();
        config.WristbandApplicationVanityDomain = null;

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("WristbandApplicationVanityDomain", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenTokenExpirationBufferIsNegative()
    {
        var config = CreateValidConfig();
        config.TokenExpirationBuffer = -1;

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("TokenExpirationBuffer", ex.Message);
    }

    // ////////////////////////////////////
    //  AUTO-CONFIGURE DISABLED VALIDATION
    // ////////////////////////////////////

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenAutoConfigDisabled_AndLoginUrlMissing()
    {
        var config = CreateValidConfig();
        config.AutoConfigureEnabled = false;
        config.LoginUrl = null;

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("LoginUrl", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenAutoConfigDisabled_AndRedirectUriMissing()
    {
        var config = CreateValidConfig();
        config.AutoConfigureEnabled = false;
        config.RedirectUri = null;

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("RedirectUri", ex.Message);
    }

    // ////////////////////////////////////
    //  TENANT NAME TOKEN VALIDATION
    // ////////////////////////////////////

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenLoginUrlHasToken_ButNoTenantParsing()
    {
        var config = CreateValidConfig();
        config.LoginUrl = "https://{tenant_name}.example.com/login";
        config.ParseTenantFromRootDomain = null; // No tenant parsing

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("tenant_name", ex.Message);
        Assert.Contains("LoginUrl", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenRedirectUriHasToken_ButNoTenantParsing()
    {
        var config = CreateValidConfig();
        config.RedirectUri = "https://{tenant_name}.example.com/callback";
        config.ParseTenantFromRootDomain = null; // No tenant parsing

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("tenant_name", ex.Message);
        Assert.Contains("RedirectUri", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenTenantParsing_ButLoginUrlMissingToken()
    {
        var config = CreateValidConfig();
        config.LoginUrl = "https://example.com/login"; // Missing token
        config.ParseTenantFromRootDomain = "example.com"; // Tenant parsing enabled

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("tenant_name", ex.Message);
        Assert.Contains("LoginUrl", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenTenantParsing_ButRedirectUriMissingToken()
    {
        var config = CreateValidConfig();
        config.LoginUrl = "https://{tenant_name}.example.com/login"; // Has token
        config.RedirectUri = "https://example.com/callback"; // Missing token
        config.ParseTenantFromRootDomain = "example.com"; // Tenant parsing enabled

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("tenant_name", ex.Message);
        Assert.Contains("RedirectUri", ex.Message);
    }

    // ////////////////////////////////////
    //  AUTO-CONFIGURE ENABLED TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_ShouldSucceed_WhenAutoConfigEnabled_WithMinimalConfig()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = true // Will fetch config from SDK
        };

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_ShouldSucceed_WhenAutoConfigEnabled_WithPartialManualConfig()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = true,
            LoginUrl = "https://manual.example.com/login", // Manual override
            // RedirectUri will come from auto-config
        };

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenAutoConfigEnabled_WithInconsistentTenantConfig()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = true,
            LoginUrl = "https://example.com/login", // No token
            ParseTenantFromRootDomain = "example.com" // But parsing enabled
        };

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("tenant_name", ex.Message);
    }

    // ////////////////////////////////////
    //  VALID CONFIGURATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_ShouldSucceed_WithValidTenantConfiguration()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://{tenant_name}.example.com/login",
            RedirectUri = "https://{tenant_name}.example.com/callback",
            ParseTenantFromRootDomain = "example.com",
            LoginStateSecret = new string('a', 32)
        };

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_ShouldSucceed_WithoutTenantConfiguration()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback"
            // No ParseTenantFromRootDomain
        };

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_ShouldSucceed_WithAllOptionalParameters()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback",
            LoginStateSecret = new string('a', 32),
            Scopes = new List<string> { "custom", "scopes" },
            IsApplicationCustomDomainActive = true,
            DangerouslyDisableSecureCookies = true,
            CustomApplicationLoginPageUrl = "https://custom.example.com/login",
            TokenExpirationBuffer = 120
        };

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    // ////////////////////////////////////
    //  EDGE CASES AND ERROR CONDITIONS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_ShouldThrowArgumentNullException_WhenConfigIsNull()
    {
        Assert.Throws<ArgumentNullException>(() => new WristbandAuthService(null!));
    }

    [Fact]
    public void Constructor_ShouldSucceed_WithZeroTokenExpirationBuffer()
    {
        var config = CreateValidConfig();
        config.TokenExpirationBuffer = 0;

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_ShouldSucceed_WithEmptyScopes()
    {
        var config = CreateValidConfig();
        config.Scopes = new List<string>(); // Empty list should use defaults

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    [Fact]
    public void Constructor_ShouldSucceed_WithNullScopes()
    {
        var config = CreateValidConfig();
        config.Scopes = null; // Null should use defaults

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }

    ////////////////////////////////////////////////////////
    /// BACKWARDS COMPATIBILITY TESTS FOR {tenant_domain}
    ////////////////////////////////////////////////////////

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenLoginUrlHasTenantDomainToken_ButNoTenantParsing_BackwardsCompat()
    {
        var config = CreateValidConfig();
        config.LoginUrl = "https://{tenant_domain}.example.com/login";
        config.ParseTenantFromRootDomain = null; // No tenant parsing

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("tenant_name", ex.Message);
        Assert.Contains("LoginUrl", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenRedirectUriHasTenantDomainToken_ButNoTenantParsing_BackwardsCompat()
    {
        var config = CreateValidConfig();
        config.RedirectUri = "https://{tenant_domain}.example.com/callback";
        config.ParseTenantFromRootDomain = null; // No tenant parsing

        var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
        Assert.Contains("tenant_name", ex.Message);
        Assert.Contains("RedirectUri", ex.Message);
    }

    [Fact]
    public void Constructor_ShouldSucceed_WithValidTenantDomainTokenConfiguration_BackwardsCompat()
    {
        var config = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            WristbandApplicationVanityDomain = "example.wristband.dev",
            AutoConfigureEnabled = false,
            LoginUrl = "https://{tenant_domain}.example.com/login",
            RedirectUri = "https://{tenant_domain}.example.com/callback",
            ParseTenantFromRootDomain = "example.com",
            LoginStateSecret = new string('a', 32)
        };

        var service = new WristbandAuthService(config);
        Assert.NotNull(service);
    }
}
