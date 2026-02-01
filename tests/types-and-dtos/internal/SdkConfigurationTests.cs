using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests;

public class SdkConfigurationTests
{
    [Fact]
    public void DefaultConstructor_ShouldInitializePropertiesWithDefaults()
    {
        var config = new SdkConfiguration();

        Assert.Null(config.CustomApplicationLoginPageUrl);
        Assert.False(config.IsApplicationCustomDomainActive);
        Assert.Equal(string.Empty, config.LoginUrl);
        Assert.Null(config.LoginUrlTenantDomainSuffix);
        Assert.Equal(string.Empty, config.RedirectUri);
    }

    [Fact]
    public void CustomApplicationLoginPageUrl_ShouldBeSettableAfterConstruction()
    {
        var config = new SdkConfiguration();
        var url = "https://custom-login.example.com";

        config.CustomApplicationLoginPageUrl = url;

        Assert.Equal(url, config.CustomApplicationLoginPageUrl);
    }

    [Fact]
    public void CustomApplicationLoginPageUrl_ShouldAcceptNull()
    {
        var config = new SdkConfiguration();

        config.CustomApplicationLoginPageUrl = null;

        Assert.Null(config.CustomApplicationLoginPageUrl);
    }

    [Fact]
    public void IsApplicationCustomDomainActive_ShouldBeSettableAfterConstruction()
    {
        var config = new SdkConfiguration();

        config.IsApplicationCustomDomainActive = true;

        Assert.True(config.IsApplicationCustomDomainActive);
    }

    [Fact]
    public void IsApplicationCustomDomainActive_ShouldDefaultToFalse()
    {
        var config = new SdkConfiguration();

        Assert.False(config.IsApplicationCustomDomainActive);
    }

    [Fact]
    public void LoginUrl_ShouldBeSettableAfterConstruction()
    {
        var config = new SdkConfiguration();
        var loginUrl = "https://myapp.com/login";

        config.LoginUrl = loginUrl;

        Assert.Equal(loginUrl, config.LoginUrl);
    }

    [Fact]
    public void LoginUrl_ShouldDefaultToEmptyString()
    {
        var config = new SdkConfiguration();

        Assert.Equal(string.Empty, config.LoginUrl);
    }

    [Fact]
    public void LoginUrl_ShouldAcceptTenantDomainToken()
    {
        var config = new SdkConfiguration();
        var loginUrl = "https://{tenant_name}.myapp.com/login";

        config.LoginUrl = loginUrl;

        Assert.Equal(loginUrl, config.LoginUrl);
    }

    [Fact]
    public void LoginUrlTenantDomainSuffix_ShouldBeSettableAfterConstruction()
    {
        var config = new SdkConfiguration();
        var suffix = ".myapp.com";

        config.LoginUrlTenantDomainSuffix = suffix;

        Assert.Equal(suffix, config.LoginUrlTenantDomainSuffix);
    }

    [Fact]
    public void LoginUrlTenantDomainSuffix_ShouldAcceptNull()
    {
        var config = new SdkConfiguration();

        config.LoginUrlTenantDomainSuffix = null;

        Assert.Null(config.LoginUrlTenantDomainSuffix);
    }

    [Fact]
    public void RedirectUri_ShouldBeSettableAfterConstruction()
    {
        var config = new SdkConfiguration();
        var redirectUri = "https://myapp.com/callback";

        config.RedirectUri = redirectUri;

        Assert.Equal(redirectUri, config.RedirectUri);
    }

    [Fact]
    public void RedirectUri_ShouldDefaultToEmptyString()
    {
        var config = new SdkConfiguration();

        Assert.Equal(string.Empty, config.RedirectUri);
    }

    [Fact]
    public void RedirectUri_ShouldAcceptTenantDomainToken()
    {
        var config = new SdkConfiguration();
        var redirectUri = "https://{tenant_name}.myapp.com/callback";

        config.RedirectUri = redirectUri;

        Assert.Equal(redirectUri, config.RedirectUri);
    }

    [Fact]
    public void JsonSerialization_ShouldUseCorrectPropertyNames()
    {
        var config = new SdkConfiguration
        {
            CustomApplicationLoginPageUrl = "https://custom.example.com",
            IsApplicationCustomDomainActive = true,
            LoginUrl = "https://login.example.com",
            LoginUrlTenantDomainSuffix = ".example.com",
            RedirectUri = "https://callback.example.com"
        };

        var json = JsonSerializer.Serialize(config);

        Assert.Contains("\"customApplicationLoginPageUrl\":", json);
        Assert.Contains("\"isApplicationCustomDomainActive\":", json);
        Assert.Contains("\"loginUrl\":", json);
        Assert.Contains("\"loginUrlTenantDomainSuffix\":", json);
        Assert.Contains("\"redirectUri\":", json);
    }

    [Fact]
    public void JsonDeserialization_ShouldMapPropertiesCorrectly()
    {
        var json = @"{
            ""customApplicationLoginPageUrl"": ""https://custom.example.com"",
            ""isApplicationCustomDomainActive"": true,
            ""loginUrl"": ""https://login.example.com"",
            ""loginUrlTenantDomainSuffix"": "".example.com"",
            ""redirectUri"": ""https://callback.example.com""
        }";

        var config = JsonSerializer.Deserialize<SdkConfiguration>(json);

        Assert.NotNull(config);
        Assert.Equal("https://custom.example.com", config.CustomApplicationLoginPageUrl);
        Assert.True(config.IsApplicationCustomDomainActive);
        Assert.Equal("https://login.example.com", config.LoginUrl);
        Assert.Equal(".example.com", config.LoginUrlTenantDomainSuffix);
        Assert.Equal("https://callback.example.com", config.RedirectUri);
    }

    [Fact]
    public void JsonDeserialization_WithNullValues_ShouldHandleCorrectly()
    {
        var json = @"{
            ""customApplicationLoginPageUrl"": null,
            ""isApplicationCustomDomainActive"": false,
            ""loginUrl"": """",
            ""loginUrlTenantDomainSuffix"": null,
            ""redirectUri"": """"
        }";

        var config = JsonSerializer.Deserialize<SdkConfiguration>(json);

        Assert.NotNull(config);
        Assert.Null(config.CustomApplicationLoginPageUrl);
        Assert.False(config.IsApplicationCustomDomainActive);
        Assert.Equal(string.Empty, config.LoginUrl);
        Assert.Null(config.LoginUrlTenantDomainSuffix);
        Assert.Equal(string.Empty, config.RedirectUri);
    }

    ////////////////////////////////////////////////////////
    /// BACKWARDS COMPATIBILITY TESTS FOR {tenant_domain}
    ////////////////////////////////////////////////////////

    [Fact]
    public void LoginUrl_ShouldAcceptTenantDomainToken_BackwardsCompat()
    {
        var config = new SdkConfiguration();
        var loginUrl = "https://{tenant_domain}.myapp.com/login";
        config.LoginUrl = loginUrl;
        Assert.Equal(loginUrl, config.LoginUrl);
    }

    [Fact]
    public void RedirectUri_ShouldAcceptTenantDomainToken_BackwardsCompat()
    {
        var config = new SdkConfiguration();
        var redirectUri = "https://{tenant_domain}.myapp.com/callback";

        config.RedirectUri = redirectUri;

        Assert.Equal(redirectUri, config.RedirectUri);
    }

    [Fact]
    public void JsonDeserialization_WithTenantDomainToken_BackwardsCompat()
    {
        var json = @"{
            ""customApplicationLoginPageUrl"": null,
            ""isApplicationCustomDomainActive"": false,
            ""loginUrl"": ""https://{tenant_domain}.example.com/login"",
            ""loginUrlTenantDomainSuffix"": "".example.com"",
            ""redirectUri"": ""https://{tenant_domain}.example.com/callback""
        }";

        var config = JsonSerializer.Deserialize<SdkConfiguration>(json);

        Assert.NotNull(config);
        Assert.Equal("https://{tenant_domain}.example.com/login", config.LoginUrl);
        Assert.Equal("https://{tenant_domain}.example.com/callback", config.RedirectUri);
    }
}
