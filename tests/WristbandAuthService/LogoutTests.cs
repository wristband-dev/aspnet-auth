using System.Reflection;

using Microsoft.AspNetCore.Http;

using Moq;

namespace Wristband.AspNet.Auth.Tests
{
    public class LogoutTests
    {
        private readonly Mock<IWristbandNetworking> _mockNetworking = new Mock<IWristbandNetworking>();
        private readonly AuthConfig _defaultConfig = new AuthConfig
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

        public LogoutTests()
        {
        }

        [Fact]
        public async Task Logout_Should_ReturnAppLoginUrl_IfNoLogoutConfigProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant.example.com");

            var logoutUrl = await service.Logout(httpContext, null);

            _mockNetworking.Verify(m => m.RevokeRefreshToken(It.IsAny<string>()), Times.Never);

            Assert.Equal("no-store", httpContext.Response.Headers["Cache-Control"]);
            Assert.Equal("no-cache", httpContext.Response.Headers["Pragma"]);
            Assert.Equal("https://example.com/login?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_RevokeRefreshToken_IfProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant.example.com");
            LogoutConfig logoutConfig = new LogoutConfig { RefreshToken = "valid-refresh-token", TenantDomainName = "tenant" };

            _mockNetworking
                .Setup(m => m.RefreshToken("valid-refresh-token"))
                .Verifiable();

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            _mockNetworking.Verify(m => m.RevokeRefreshToken("valid-refresh-token"), Times.Once);

            Assert.Equal("no-store", httpContext.Response.Headers["Cache-Control"]);
            Assert.Equal("no-cache", httpContext.Response.Headers["Pragma"]);
            Assert.Equal("https://tenant-example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_NotRevokeRefreshToken_IfNotProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant.example.com");
            LogoutConfig logoutConfig = new LogoutConfig { TenantDomainName = "tenant" };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            _mockNetworking.Verify(m => m.RevokeRefreshToken(It.IsAny<string>()), Times.Never);

            Assert.Equal("no-store", httpContext.Response.Headers["Cache-Control"]);
            Assert.Equal("no-cache", httpContext.Response.Headers["Pragma"]);
            Assert.Equal("https://tenant-example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_ReturnCustomRedirectUrl_IfProvided()
        {
            WristbandAuthService service = setupWristbandAuthService(_defaultConfig);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant.example.com");
            LogoutConfig logoutConfig = new LogoutConfig { RedirectUrl = "https://redirect.com" };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            _mockNetworking.Verify(m => m.RevokeRefreshToken(It.IsAny<string>()), Times.Never);

            Assert.Equal("no-store", httpContext.Response.Headers["Cache-Control"]);
            Assert.Equal("no-cache", httpContext.Response.Headers["Pragma"]);
            Assert.Equal("https://redirect.com", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_HandleTenantSubdomains_Correctly()
        {
            AuthConfig config = new AuthConfig
            {
                ClientId = "valid-client-id",
                ClientSecret = "valid-client-secret",
                LoginStateSecret = new string('a', 32), // At least 32 characters
                LoginUrl = "https://{tenant_domain}.example.com/login",
                RedirectUri = "https://{tenant_domain}.example.com/callback",
                WristbandApplicationDomain = "example.com",
                RootDomain = "example.com",
                UseTenantSubdomains = true
            };
            WristbandAuthService service = setupWristbandAuthService(config);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant.example.com");
            LogoutConfig logoutConfig = new LogoutConfig { TenantDomainName = "tenant" };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            _mockNetworking.Verify(m => m.RevokeRefreshToken(It.IsAny<string>()), Times.Never);

            Assert.Equal("https://tenant-example.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        [Fact]
        public async Task Logout_Should_HandleCustomTenantDomain()
        {
            AuthConfig config = new AuthConfig
            {
                ClientId = "valid-client-id",
                ClientSecret = "valid-client-secret",
                LoginStateSecret = new string('a', 32), // At least 32 characters
                LoginUrl = "https://{tenant_domain}.example.com/login",
                RedirectUri = "https://{tenant_domain}.example.com/callback",
                WristbandApplicationDomain = "example.com",
                RootDomain = "example.com",
                UseTenantSubdomains = true,
                UseCustomDomains = true,
            };
            WristbandAuthService service = setupWristbandAuthService(config);
            HttpContext httpContext = TestUtils.setupHttpContext("tenant.example.com");
            LogoutConfig logoutConfig = new LogoutConfig { TenantDomainName = "tenant", TenantCustomDomain = "custom.com" };

            var logoutUrl = await service.Logout(httpContext, logoutConfig);

            Assert.Equal("https://custom.com/api/v1/logout?client_id=valid-client-id", logoutUrl);
        }

        private WristbandAuthService setupWristbandAuthService(AuthConfig authConfig)
        {
            WristbandAuthService wristbandAuthService = new WristbandAuthService(authConfig);

            // Use reflection to inject the mock networking object into the service
            var fieldInfo = typeof(WristbandAuthService).GetField("mWristbandNetworking", BindingFlags.NonPublic | BindingFlags.Instance);
            if (fieldInfo != null && _mockNetworking != null)
            {
                fieldInfo.SetValue(wristbandAuthService, _mockNetworking.Object);
            }

            return wristbandAuthService;
        }
    }
}
