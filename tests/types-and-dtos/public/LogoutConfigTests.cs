namespace Wristband.AspNet.Auth.Tests
{
    public class LogoutConfigTests
    {
        [Fact]
        public void Constructor_WithValidValues_SetsProperties()
        {
            // Arrange
            var redirectUrl = "https://example.com/logout";
            var refreshToken = "sampleRefreshToken";
            var state = "customStateValue";
            var tenantCustomDomain = "tenant.custom.domain";
            var tenantDomainName = "tenant.domain.name";

            // Act
            var logoutConfig = new LogoutConfig(redirectUrl, refreshToken, state, tenantCustomDomain, tenantDomainName);

            // Assert
            Assert.Equal(redirectUrl, logoutConfig.RedirectUrl);
            Assert.Equal(refreshToken, logoutConfig.RefreshToken);
            Assert.Equal(state, logoutConfig.State);
            Assert.Equal(tenantCustomDomain, logoutConfig.TenantCustomDomain);
            Assert.Equal(tenantDomainName, logoutConfig.TenantDomainName);
        }

        [Fact]
        public void Constructor_WithNoValues_SetsNullValues()
        {
            // Act
            var logoutConfig = new LogoutConfig();

            // Assert
            Assert.Null(logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Null(logoutConfig.State);
            Assert.Null(logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantDomainName);
        }

        [Fact]
        public void Constructor_WithNullValues_SetsNullValues()
        {
            // Act
            var logoutConfig = new LogoutConfig(null, null, null, null, null);

            // Assert
            Assert.Null(logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Null(logoutConfig.State);
            Assert.Null(logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantDomainName);
        }

        [Fact]
        public void Constructor_WithSomeNullValues_SetsCorrectValues()
        {
            // Arrange
            var redirectUrl = "https://example.com/logout";
            string? refreshToken = null;
            var state = "testState";
            var tenantCustomDomain = "tenant.custom.domain";
            string? tenantDomainName = null;

            // Act
            var logoutConfig = new LogoutConfig(redirectUrl, refreshToken, state, tenantCustomDomain, tenantDomainName);

            // Assert
            Assert.Equal(redirectUrl, logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Equal(state, logoutConfig.State);
            Assert.Equal(tenantCustomDomain, logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantDomainName);
        }

        [Fact]
        public void Properties_CanBeSetIndividually()
        {
            // Arrange
            var logoutConfig = new LogoutConfig();

            // Act
            logoutConfig.RedirectUrl = "https://example.com/logout";
            logoutConfig.RefreshToken = "testToken";
            logoutConfig.State = "testState";
            logoutConfig.TenantCustomDomain = "custom.domain";
            logoutConfig.TenantDomainName = "domain.name";

            // Assert
            Assert.Equal("https://example.com/logout", logoutConfig.RedirectUrl);
            Assert.Equal("testToken", logoutConfig.RefreshToken);
            Assert.Equal("testState", logoutConfig.State);
            Assert.Equal("custom.domain", logoutConfig.TenantCustomDomain);
            Assert.Equal("domain.name", logoutConfig.TenantDomainName);
        }
    }
}
