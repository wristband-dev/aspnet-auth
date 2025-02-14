namespace Wristband.AspNet.Auth.Tests
{
    public class WristbandAuthServiceConstructorTests
    {
        private AuthConfig GetValidAuthConfig()
        {
            return new AuthConfig
            {
                ClientId = "valid-client-id",
                ClientSecret = "valid-client-secret",
                LoginStateSecret = new string('a', 32), // At least 32 characters
                LoginUrl = "https://example.com/login",
                RedirectUri = "https://example.com/callback",
                WristbandApplicationDomain = "example.com",
                RootDomain = "example.com",
                UseTenantSubdomains = false
            };
        }

        [Fact]
        public void DefaultConstructor_ShouldCallParameterizedConstructor_WithNullHttpClient()
        {
            var config = GetValidAuthConfig();
            var service = new WristbandAuthService(config);

            Assert.NotNull(service);

            var scopesField = typeof(WristbandAuthService).GetField("mScopes",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var scopes = scopesField?.GetValue(service) as List<string>;
            Assert.Equal(new List<string> { "openid", "offline_access", "email" }, scopes);
        }

        [Fact]
        public void ParameterizedConstructor_ShouldAcceptNullHttpClient()
        {
            var config = GetValidAuthConfig();
            var service = new WristbandAuthService(config, null);
            Assert.NotNull(service);
        }

        [Fact]
        public void ParameterizedConstructor_ShouldAcceptCustomHttpClient()
        {
            var config = GetValidAuthConfig();
            var httpClient = new HttpClient();
            var service = new WristbandAuthService(config, httpClient);
            Assert.NotNull(service);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenClientIdIsNullOrEmpty()
        {
            var config = GetValidAuthConfig();
            config.ClientId = "";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [clientId] config must have a value.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenClientSecretIsNullOrEmpty()
        {
            var config = GetValidAuthConfig();
            config.ClientSecret = "";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [clientSecret] config must have a value.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenLoginStateSecretIsNullOrEmpty()
        {
            var config = GetValidAuthConfig();
            config.LoginStateSecret = "";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [loginStateSecret] config must have a value of at least 32 characters.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenLoginStateSecretIsLessThan32Characters()
        {
            var config = GetValidAuthConfig();
            config.LoginStateSecret = "short_secret";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [loginStateSecret] config must have a value of at least 32 characters.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenLoginUrlIsNullOrEmpty()
        {
            var config = GetValidAuthConfig();
            config.LoginUrl = "";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [loginUrl] config must have a value.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenRedirectUriIsNullOrEmpty()
        {
            var config = GetValidAuthConfig();
            config.RedirectUri = "";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [redirectUri] config must have a value.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenLoginUrlContainsTenantDomainToken_AndUseTenantSubdomainsIsFalse()
        {
            var config = GetValidAuthConfig();
            config.UseTenantSubdomains = false;
            config.LoginUrl = "https://{tenant_domain}.example.com/login";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [loginUrl] cannot contain the \"{tenant_domain}\" token when tenant subdomains are not used.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenRedirectUriContainsTenantDomainToken_AndUseTenantSubdomainsIsFalse()
        {
            var config = GetValidAuthConfig();
            config.UseTenantSubdomains = false;
            config.RedirectUri = "https://{tenant_domain}.example.com/callback";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [redirectUri] cannot contain the \"{tenant_domain}\" token when tenant subdomains are not used.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldUseDefaultScopes_WhenScopesNotProvided()
        {
            var config = GetValidAuthConfig();
            config.Scopes = null;

            var service = new WristbandAuthService(config);

            var scopesField = typeof(WristbandAuthService).GetField("mScopes",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            Assert.NotNull(scopesField);
            var scopes = scopesField.GetValue(service) as List<string>;
            Assert.NotNull(scopes);
            Assert.Equal(new List<string> { "openid", "offline_access", "email" }, scopes);
        }

        [Fact]
        public void Constructor_ShouldUseProvidedScopes_WhenScopesSpecified()
        {
            var config = GetValidAuthConfig();
            config.Scopes = new List<string> { "custom_scope1", "custom_scope2" };

            var service = new WristbandAuthService(config);

            var scopesField = typeof(WristbandAuthService).GetField("mScopes",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            Assert.NotNull(scopesField);
            var scopes = scopesField.GetValue(service) as List<string>;
            Assert.NotNull(scopes);
            Assert.Equal(config.Scopes, scopes);
        }

        [Fact]
        public void Constructor_ShouldSetDefaultValues_WhenOptionalParametersNotProvided()
        {
            var config = GetValidAuthConfig();
            config.UseCustomDomains = null;
            config.DangerouslyDisableSecureCookies = null;
            config.CustomApplicationLoginPageUrl = null;

            var service = new WristbandAuthService(config);

            var useCustomDomainsField = typeof(WristbandAuthService).GetField("mUseCustomDomains",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var dangerouslyDisableSecureCookiesField = typeof(WristbandAuthService).GetField("mDangerouslyDisableSecureCookies",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var customApplicationLoginPageUrlField = typeof(WristbandAuthService).GetField("mCustomApplicationLoginPageUrl",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            Assert.NotNull(useCustomDomainsField);
            Assert.NotNull(dangerouslyDisableSecureCookiesField);
            Assert.NotNull(customApplicationLoginPageUrlField);

            Assert.False((bool)useCustomDomainsField.GetValue(service)!);
            Assert.False((bool)dangerouslyDisableSecureCookiesField.GetValue(service)!);
            Assert.Equal(string.Empty, (string)customApplicationLoginPageUrlField.GetValue(service)!);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenWristbandApplicationDomainIsEmpty()
        {
            var config = GetValidAuthConfig();
            config.WristbandApplicationDomain = "";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [wristbandApplicationDomain] config must have a value.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenUseTenantSubdomainsTrue_AndRootDomainEmpty()
        {
            var config = GetValidAuthConfig();
            config.UseTenantSubdomains = true;
            config.RootDomain = "";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [rootDomain] config must have a value when using tenant subdomains.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenUseTenantSubdomainsTrue_AndLoginUrlMissingToken()
        {
            var config = GetValidAuthConfig();
            config.UseTenantSubdomains = true;
            config.LoginUrl = "https://example.com/login";
            config.RootDomain = "example.com";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [loginUrl] must contain the \"{tenant_domain}\" token when using tenant subdomains.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowArgumentException_WhenUseTenantSubdomainsTrue_AndRedirectUriMissingToken()
        {
            var config = GetValidAuthConfig();
            config.UseTenantSubdomains = true;
            config.RedirectUri = "https://example.com/callback";
            config.RootDomain = "example.com";
            config.LoginUrl = "https://{tenant_domain}.example.com/login";

            var ex = Assert.Throws<ArgumentException>(() => new WristbandAuthService(config));
            Assert.Equal("The [redirectUri] must contain the \"{tenant_domain}\" token when using tenant subdomains.", ex.Message);
        }

        [Fact]
        public void Constructor_ShouldSucceed_WhenAllConfigurationValid()
        {
            var config = GetValidAuthConfig();
            config.UseTenantSubdomains = true;
            config.LoginUrl = "https://{tenant_domain}.example.com/login";
            config.RedirectUri = "https://{tenant_domain}.example.com/callback";
            config.Scopes = new List<string> { "custom_scope" };
            config.UseCustomDomains = true;
            config.DangerouslyDisableSecureCookies = true;
            config.CustomApplicationLoginPageUrl = "https://custom.example.com/login";

            var service = new WristbandAuthService(config);

            Assert.NotNull(service);
        }
    }
}
