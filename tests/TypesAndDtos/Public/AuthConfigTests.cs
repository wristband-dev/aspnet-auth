using System;
using System.Collections.Generic;

using Xunit;

namespace Wristband.AspNet.Auth.Tests
{
    public class AuthConfigTests
    {
        [Fact]
        public void DefaultConstructor_ShouldInitializePropertiesWithDefaults()
        {
            var config = new AuthConfig();

            Assert.Null(config.ClientId);
            Assert.Null(config.ClientSecret);
            Assert.Null(config.LoginStateSecret);
            Assert.Null(config.LoginUrl);
            Assert.Null(config.RedirectUri);
            Assert.Null(config.WristbandApplicationDomain);
            Assert.Null(config.CustomApplicationLoginPageUrl);
            Assert.Null(config.RootDomain);
            Assert.NotNull(config.Scopes);
            Assert.Empty(config.Scopes);
            Assert.False(config.DangerouslyDisableSecureCookies);
            Assert.False(config.UseCustomDomains);
            Assert.False(config.UseTenantSubdomains);
        }

        [Fact]
        public void Constructor_WithValidValues_ShouldSetProperties()
        {
            var clientId = "test-client-id";
            var clientSecret = "test-client-secret";
            var loginStateSecret = "test-login-state-secret";
            var loginUrl = "https://login.example.com";
            var redirectUri = "https://app.example.com/callback";
            var wristbandApplicationDomain = "wristband.example.com";
            var customApplicationLoginPageUrl = "https://custom-login.example.com";
            var dangerouslyDisableSecureCookies = true;
            var rootDomain = "example.com";
            var scopes = new List<string> { "openid", "profile", "email" };
            var useCustomDomains = true;
            var useTenantSubdomains = true;

            var config = new AuthConfig(
                clientId,
                clientSecret,
                loginStateSecret,
                loginUrl,
                redirectUri,
                wristbandApplicationDomain,
                customApplicationLoginPageUrl,
                dangerouslyDisableSecureCookies,
                rootDomain,
                scopes,
                useCustomDomains,
                useTenantSubdomains
            );

            Assert.Equal(clientId, config.ClientId);
            Assert.Equal(clientSecret, config.ClientSecret);
            Assert.Equal(loginStateSecret, config.LoginStateSecret);
            Assert.Equal(loginUrl, config.LoginUrl);
            Assert.Equal(redirectUri, config.RedirectUri);
            Assert.Equal(wristbandApplicationDomain, config.WristbandApplicationDomain);
            Assert.Equal(customApplicationLoginPageUrl, config.CustomApplicationLoginPageUrl);
            Assert.Equal(rootDomain, config.RootDomain);
            Assert.NotNull(config.Scopes);
            Assert.Equal(scopes, config.Scopes);
            Assert.True(config.DangerouslyDisableSecureCookies);
            Assert.True(config.UseCustomDomains);
            Assert.True(config.UseTenantSubdomains);
        }

        [Fact]
        public void Constructor_WithNullValues_ShouldSetPropertiesToNullOrDefaults()
        {
            var config = new AuthConfig(null, null, null, null, null, null, null, null, null, null, null, null);

            Assert.Null(config.ClientId);
            Assert.Null(config.ClientSecret);
            Assert.Null(config.LoginStateSecret);
            Assert.Null(config.LoginUrl);
            Assert.Null(config.RedirectUri);
            Assert.Null(config.WristbandApplicationDomain);
            Assert.Null(config.CustomApplicationLoginPageUrl);
            Assert.Null(config.RootDomain);
            Assert.Null(config.Scopes);
            Assert.Null(config.DangerouslyDisableSecureCookies);
            Assert.Null(config.UseCustomDomains);
            Assert.Null(config.UseTenantSubdomains);
        }

        [Fact]
        public void Properties_ShouldBeSettableAfterConstruction()
        {
            var config = new AuthConfig();

            config.ClientId = "updated-client-id";
            config.ClientSecret = "updated-client-secret";
            config.LoginStateSecret = "updated-login-state-secret";
            config.LoginUrl = "https://updated-login.example.com";
            config.RedirectUri = "https://updated.example.com/callback";
            config.WristbandApplicationDomain = "updated-wristband.example.com";
            config.CustomApplicationLoginPageUrl = "https://updated-custom-login.example.com";
            config.DangerouslyDisableSecureCookies = true;
            config.RootDomain = "updated-example.com";
            config.Scopes = new List<string> { "custom-scope" };
            config.UseCustomDomains = true;
            config.UseTenantSubdomains = true;

            Assert.Equal("updated-client-id", config.ClientId);
            Assert.Equal("updated-client-secret", config.ClientSecret);
            Assert.Equal("updated-login-state-secret", config.LoginStateSecret);
            Assert.Equal("https://updated-login.example.com", config.LoginUrl);
            Assert.Equal("https://updated.example.com/callback", config.RedirectUri);
            Assert.Equal("updated-wristband.example.com", config.WristbandApplicationDomain);
            Assert.Equal("https://updated-custom-login.example.com", config.CustomApplicationLoginPageUrl);
            Assert.Equal("updated-example.com", config.RootDomain);
            Assert.NotNull(config.Scopes);
            Assert.Single(config.Scopes);
            Assert.Equal("custom-scope", config.Scopes[0]);
            Assert.True(config.DangerouslyDisableSecureCookies);
            Assert.True(config.UseCustomDomains);
            Assert.True(config.UseTenantSubdomains);
        }
    }
}
