using System;

using Xunit;

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
            var tenantCustomDomain = "tenant.custom.domain";
            var tenantDomainName = "tenant.domain.name";

            // Act
            var logoutConfig = new LogoutConfig(redirectUrl, refreshToken, tenantCustomDomain, tenantDomainName);

            // Assert
            Assert.Equal(redirectUrl, logoutConfig.RedirectUrl);
            Assert.Equal(refreshToken, logoutConfig.RefreshToken);
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
            Assert.Null(logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantDomainName);
        }

        [Fact]
        public void Constructor_WithNullValues_SetsNullValues()
        {
            // Act
            var logoutConfig = new LogoutConfig(null, null, null, null);

            // Assert
            Assert.Null(logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Null(logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantDomainName);
        }

        [Fact]
        public void Constructor_WithSomeNullValues_SetsCorrectValues()
        {
            // Arrange
            var redirectUrl = "https://example.com/logout";
            string? refreshToken = null;
            var tenantCustomDomain = "tenant.custom.domain";
            string? tenantDomainName = null;

            // Act
            var logoutConfig = new LogoutConfig(redirectUrl, refreshToken, tenantCustomDomain, tenantDomainName);

            // Assert
            Assert.Equal(redirectUrl, logoutConfig.RedirectUrl);
            Assert.Null(logoutConfig.RefreshToken);
            Assert.Equal(tenantCustomDomain, logoutConfig.TenantCustomDomain);
            Assert.Null(logoutConfig.TenantDomainName);
        }
    }
}
