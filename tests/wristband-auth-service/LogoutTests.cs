using System.Reflection;

using Microsoft.AspNetCore.Http;

using Moq;

namespace Wristband.AspNet.Auth.Tests
{
    public class LogoutTests
    {
        private readonly Mock<IWristbandApiClient> _mockApiClient = new Mock<IWristbandApiClient>();
        private readonly WristbandAuthConfig _defaultConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback",
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = false,
        };

        [Fact]
        public async Task Logout_Should_ReturnAppLoginUrl_IfNoLogoutConfigProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant.example.com");

            var logoutUrl = await service.Logout(httpContext, null);

            _mockApiClient.Verify(m => m.RevokeRefreshToken(It.IsAny<string>()), Times.Never);
            Assert.Equal("no-store", httpContext.Response.Headers["Cache-Control"]);
            Assert.Equal("no-cache", httpContext.Response.Headers["Pragma"]);
            Assert.Equal("https://example.com/login?client_id=valid-client-id", logoutUrl);
        }

        // Test Priority 1: LogoutConfig.TenantCustomDomain (highest priority)
        [Fact]
        public async Task Logout_Should_UseTenantCustomDomainFromConfig_WhenProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                TenantCustomDomain = "custom-tenant.com"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://custom-tenant.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_UseTenantCustomDomainFromConfig_EvenWhenOtherOptionsAvailable()
        {
            var config = new WristbandAuthConfig
            {
                ClientId = "valid-client-id",
                ClientSecret = "valid-client-secret",
                LoginStateSecret = new string('a', 32),
                LoginUrl = "https://{tenant_domain}.example.com/login",  // Fixed: Added {tenant_domain} token
                RedirectUri = "https://{tenant_domain}.example.com/callback",  // Fixed: Added {tenant_domain} token
                WristbandApplicationVanityDomain = "example.com",
                ParseTenantFromRootDomain = "example.com",
                AutoConfigureEnabled = false,
            };
            WristbandAuthService service = setupWristbandAuthService(config);

            // Setup context with tenant subdomain AND query param
            var httpContext = TestUtils.setupHttpContext("tenant.example.com");
            httpContext.Request.QueryString = new QueryString("?tenant_custom_domain=query-custom.com");

            LogoutConfig logoutConfig = new LogoutConfig
            {
                TenantCustomDomain = "config-custom.com",  // This should take priority
                TenantDomainName = "config-tenant"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://config-custom.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        // Test Priority 2: LogoutConfig.TenantDomainName
        [Fact]
        public async Task Logout_Should_UseTenantDomainFromConfig_WhenNoCustomDomain()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                TenantDomainName = "config-tenant"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://config-tenant-example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_UseTenantDomainFromConfig_WithCustomDomainSeparator()
        {
            var config = new WristbandAuthConfig
            {
                ClientId = "valid-client-id",
                ClientSecret = "valid-client-secret",
                LoginStateSecret = new string('a', 32),
                LoginUrl = "https://example.com/login",
                RedirectUri = "https://example.com/callback",
                WristbandApplicationVanityDomain = "example.com",
                IsApplicationCustomDomainActive = true,  // This changes separator from '-' to '.'
                AutoConfigureEnabled = false,
            };
            WristbandAuthService service = setupWristbandAuthService(config);
            HttpContext httpContext = TestUtils.setupHttpContext("some-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                TenantDomainName = "config-tenant"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://config-tenant.example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        // Test Priority 3: tenant_custom_domain query parameter
        [Fact]
        public async Task Logout_Should_UseTenantCustomDomainFromQuery_WhenNoConfigOptions()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            var httpContext = TestUtils.setupHttpContext("some-host.com");
            httpContext.Request.QueryString = new QueryString("?tenant_custom_domain=query-custom.com");

            var logoutUrl = await service.Logout(httpContext, new LogoutConfig());

            Assert.Equal("https://query-custom.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        // Test Priority 4a: Tenant from subdomain (when ParseTenantFromRootDomain is set)
        [Fact]
        public async Task Logout_Should_UseTenantFromSubdomain_WhenParseFromRootDomainSet()
        {
            var config = new WristbandAuthConfig
            {
                ClientId = "valid-client-id",
                ClientSecret = "valid-client-secret",
                LoginStateSecret = new string('a', 32),
                LoginUrl = "https://{tenant_domain}.example.com/login",
                RedirectUri = "https://{tenant_domain}.example.com/callback",
                WristbandApplicationVanityDomain = "example.com",
                ParseTenantFromRootDomain = "example.com",
                AutoConfigureEnabled = false,
            };
            WristbandAuthService service = setupWristbandAuthService(config);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant-from-subdomain.example.com");

            var logoutUrl = await service.Logout(httpContext, new LogoutConfig());

            Assert.Equal("https://tenant-from-subdomain-example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        // Test Priority 4b: Tenant from query parameter (when ParseTenantFromRootDomain is NOT set)
        [Fact]
        public async Task Logout_Should_UseTenantFromQuery_WhenParseFromRootDomainNotSet()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            var httpContext = TestUtils.setupHttpContext("some-host.com");
            httpContext.Request.QueryString = new QueryString("?tenant_domain=query-tenant");

            var logoutUrl = await service.Logout(httpContext, new LogoutConfig());

            Assert.Equal("https://query-tenant-example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        // Test fallback scenarios
        [Fact]
        public async Task Logout_Should_FallbackToAppLogin_WhenNoTenantResolved()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-random-host.com");

            var logoutUrl = await service.Logout(httpContext, new LogoutConfig());

            Assert.Equal("https://example.com/login?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_FallbackToCustomAppLogin_WhenConfigured()
        {
            var config = new WristbandAuthConfig
            {
                ClientId = "valid-client-id",
                ClientSecret = "valid-client-secret",
                LoginStateSecret = new string('a', 32),
                LoginUrl = "https://example.com/login",
                RedirectUri = "https://example.com/callback",
                WristbandApplicationVanityDomain = "example.com",
                CustomApplicationLoginPageUrl = "https://custom-login.com",
                AutoConfigureEnabled = false,
            };
            WristbandAuthService service = setupWristbandAuthService(config);
            HttpContext httpContext = TestUtils.setupHttpContext("some-random-host.com");

            var logoutUrl = await service.Logout(httpContext, new LogoutConfig());

            Assert.Equal("https://custom-login.com?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_UseRedirectUrl_WhenNoTenantAndRedirectProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-random-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                RedirectUrl = "https://custom-redirect.com"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://custom-redirect.com", logoutUrl);
        }

        // Test redirect URL parameter inclusion
        [Fact]
        public async Task Logout_Should_IncludeRedirectUrlParam_WhenTenantResolvedAndRedirectProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            var httpContext = TestUtils.setupHttpContext("some-host.com");
            httpContext.Request.QueryString = new QueryString("?tenant_domain=test-tenant");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                RedirectUrl = "https://post-logout.com"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://test-tenant-example.com/api/v1/logout?client_id=valid-client-id&redirect_url=https://post-logout.com", logoutUrl);
        }

        // Test refresh token revocation scenarios
        [Fact]
        public async Task Logout_Should_RevokeRefreshToken_AndUseTenantFromConfig()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                RefreshToken = "test-refresh-token",
                TenantDomainName = "config-tenant"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            _mockApiClient.Verify(m => m.RevokeRefreshToken("test-refresh-token"), Times.Once);
            Assert.Equal("https://config-tenant-example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_RevokeRefreshToken_AndFallbackWhenNoTenantResolved()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-random-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                RefreshToken = "test-refresh-token"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            _mockApiClient.Verify(m => m.RevokeRefreshToken("test-refresh-token"), Times.Once);
            Assert.Equal("https://example.com/login?client_id=valid-client-id", logoutUrl);
        }

        // Test edge cases
        [Fact]
        public async Task Logout_Should_HandleEmptyStringsInConfig()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                TenantCustomDomain = "",
                TenantDomainName = "",
                RefreshToken = "", // Empty string (should not be revoked)
                State = "",
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            _mockApiClient.Verify(m => m.RevokeRefreshToken(It.IsAny<string>()), Times.Never);
            Assert.Equal("https://example.com/login?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_HandleWhitespaceInConfig()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                TenantCustomDomain = "   ",
                TenantDomainName = "   ",
                RefreshToken = "   ", // Whitespace only - now treated as invalid (not revoked)
                State = "   ",
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            // With IsNullOrWhiteSpace, whitespace-only refresh tokens are not revoked
            _mockApiClient.Verify(m => m.RevokeRefreshToken(It.IsAny<string>()), Times.Never);
            // Since both tenant fields are whitespace-only, it falls back to app login
            Assert.Equal("https://example.com/login?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_ThrowException_WhenStateExceeds512Characters()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("some-host.com");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                State = new string('a', 513)
            };

            var exception = await Assert.ThrowsAsync<ArgumentException>(
                () => service.Logout(httpContext, logoutConfig));

            Assert.Equal("The [state] logout config cannot exceed 512 characters.", exception.Message);
        }

        [Fact]
        public async Task Logout_Should_IncludeStateParam_WhenStateProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            var httpContext = TestUtils.setupHttpContext("some-host.com");
            httpContext.Request.QueryString = new QueryString("?tenant_domain=test-tenant");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                State = "custom-state-value"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://test-tenant-example.com/api/v1/logout?client_id=valid-client-id&state=custom-state-value", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_UrlEncodeStateParam_WhenStateContainsSpecialCharacters()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            var httpContext = TestUtils.setupHttpContext("some-host.com");
            httpContext.Request.QueryString = new QueryString("?tenant_domain=test-tenant");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                State = "state with spaces & special chars"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Contains("state=state%20with%20spaces%20%26%20special%20chars", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_IncludeBothRedirectUrlAndStateParams_WhenBothProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            var httpContext = TestUtils.setupHttpContext("some-host.com");
            httpContext.Request.QueryString = new QueryString("?tenant_domain=test-tenant");
            LogoutConfig logoutConfig = new LogoutConfig
            {
                RedirectUrl = "https://post-logout.com",
                State = "custom-state"
            };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://test-tenant-example.com/api/v1/logout?client_id=valid-client-id&redirect_url=https://post-logout.com&state=custom-state", logoutUrl);
        }

        private WristbandAuthService setupWristbandAuthService(WristbandAuthConfig authConfig)
        {
            WristbandAuthService wristbandAuthService = new WristbandAuthService(authConfig);

            // Use reflection to inject the mock API Client object into the service
            var fieldInfo = typeof(WristbandAuthService).GetField("_wristbandApiClient", BindingFlags.NonPublic | BindingFlags.Instance);
            if (fieldInfo != null && _mockApiClient != null)
            {
                fieldInfo.SetValue(wristbandAuthService, _mockApiClient.Object);
            }

            return wristbandAuthService;
        }
    }
}
