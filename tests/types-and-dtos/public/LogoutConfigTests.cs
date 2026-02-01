namespace Wristband.AspNet.Auth.Tests
{
    public class LogoutConfigTests
    {
        [Fact]
        public void Constructor_WithValidValues_SetsProperties()
        {
            var redirectUrl = "https://example.com/logout";
            var refreshToken = "sampleRefreshToken";
            var state = "customStateValue";
            var tenantCustomDomain = "tenant.custom.domain";
            var tenantName = "tenant.domain.name";
            var logoutConfig = new LogoutConfig(redirectUrl, refreshToken, state, tenantCustomDomain, tenantName);

            Assert.Equal(redirectUrl, logoutConfig.RedirectUrl);
            Assert.Equal(refreshToken, logoutConfig.RefreshToken);
            Assert.Equal(state, logoutConfig.State);
            Assert.Equal(tenantCustomDomain, logoutConfig.TenantCustomDomain);
            Assert.Equal(tenantName, logoutConfig.TenantName);
        }

        [Fact]
        public void Constructor_WithNoValues_SetsNullValues()
        {
            var logoutConfig = new LogoutConfig();

            Assert.Null(logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Null(logoutConfig.State);
            Assert.Null(logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantName);
        }

        [Fact]
        public void Constructor_WithNullValues_SetsNullValues()
        {
            var logoutConfig = new LogoutConfig(null, null, null, null, null);

            Assert.Null(logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Null(logoutConfig.State);
            Assert.Null(logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantName);
        }

        [Fact]
        public void Constructor_WithSomeNullValues_SetsCorrectValues()
        {
            var redirectUrl = "https://example.com/logout";
            string? refreshToken = null;
            var state = "testState";
            var tenantCustomDomain = "tenant.custom.domain";
            string? tenantName = null;
            var logoutConfig = new LogoutConfig(redirectUrl, refreshToken, state, tenantCustomDomain, tenantName);

            Assert.Equal(redirectUrl, logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Equal(state, logoutConfig.State);
            Assert.Equal(tenantCustomDomain, logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantName);
        }

        [Fact]
        public void Properties_CanBeSetIndividually()
        {
            var logoutConfig = new LogoutConfig();
            logoutConfig.RedirectUrl = "https://example.com/logout";
            logoutConfig.RefreshToken = "testToken";
            logoutConfig.State = "testState";
            logoutConfig.TenantCustomDomain = "custom.domain";
            logoutConfig.TenantName = "domain.name";

            Assert.Equal("https://example.com/logout", logoutConfig.RedirectUrl);
            Assert.Equal("testToken", logoutConfig.RefreshToken);
            Assert.Equal("testState", logoutConfig.State);
            Assert.Equal("custom.domain", logoutConfig.TenantCustomDomain);
            Assert.Equal("domain.name", logoutConfig.TenantName);
        }
    }
}
