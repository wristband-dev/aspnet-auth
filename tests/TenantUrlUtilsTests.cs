namespace Wristband.AspNet.Auth.Tests;

public class TenantUrlUtilsTests
{
    private const string RootDomain = "myapp.com";
    private const string TenantHost = "acme.myapp.com";
    private const string TenantName = "acme";

    [Theory]
    [InlineData("https://{tenant_name}.myapp.com/api/auth/login", "https://myapp.com/api/auth/login")]
    [InlineData("http://{tenant_name}.localhost:6001/api/auth/login", "http://localhost:6001/api/auth/login")]
    [InlineData("https://myapp.com/api/auth/login", "")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void DeriveFallbackLoginUrl_RemovesTenantSubdomain(string? loginUrl, string expected)
    {
        Assert.Equal(expected, TenantUrlUtils.DeriveFallbackLoginUrl(loginUrl));
    }

    [Theory]
    [InlineData("https://{tenant_name}.myapp.com/api/auth/login", "myapp.com")]
    [InlineData("http://{tenant_name}.localhost:6001/api/auth/login", "localhost")]
    [InlineData("https://myapp.com/api/auth/login", "")]
    public void DeriveTenantRootDomain_ReturnsHostnameWithoutTenantSubdomain(string loginUrl, string expected)
    {
        Assert.Equal(expected, TenantUrlUtils.DeriveTenantRootDomain(loginUrl));
    }

    [Theory]
    [InlineData("https://myapp.com/api/auth/login", true)]
    [InlineData("https://{tenant_name}.myapp.com/api/auth/login", true)]
    [InlineData("http://{tenant_name}.localhost:6001/api/auth/login", true)]
    [InlineData("https://app.{tenant_name}.myapp.com/api/auth/login", false)]
    [InlineData("https://myapp.com/{tenant_name}/api/auth/login", false)]
    [InlineData("https://{tenant_name}/api/auth/login", false)]
    [InlineData("https://{tenant_name}.myapp.com/{tenant_name}/login", false)]
    public void IsTenantPlaceholderPositionValid_ChecksLeftmostHostnamePosition(string url, bool expected)
    {
        Assert.Equal(expected, TenantUrlUtils.IsTenantPlaceholderPositionValid(url));
    }

    [Theory]
    [InlineData(null, "https", TenantHost, true, RootDomain, null)]
    [InlineData("", "https", TenantHost, true, RootDomain, null)]
    [InlineData("/settings?tab=1#top", "https", TenantHost, true, RootDomain, "/settings?tab=1#top")]
    [InlineData("https://acme.myapp.com/dashboard", "https", TenantHost, true, RootDomain, "https://acme.myapp.com/dashboard")]
    [InlineData("https://ACME.myapp.com/dashboard", "https", TenantHost, true, RootDomain, "https://ACME.myapp.com/dashboard")]
    [InlineData("https://myapp.com/dashboard", "https", TenantHost, false, RootDomain, "https://myapp.com/dashboard")]
    [InlineData("https://myapp.com/dashboard?x=1#y", "https", TenantHost, true, RootDomain, "https://acme.myapp.com/dashboard?x=1#y")]
    [InlineData("https://myapp.com:8443/home", "https", "acme.myapp.com:8443", true, RootDomain, "https://acme.myapp.com:8443/home")]
    [InlineData("https://myapp.com/dashboard", "https", "myapp.com", true, "", "https://myapp.com/dashboard")]
    [InlineData("/home", "http", "acme.localhost:6001", true, "localhost", "/home")]
    [InlineData("https://evil.com/phish", "https", TenantHost, true, RootDomain, null)]
    [InlineData("//evil.com/phish", "https", TenantHost, true, RootDomain, null)]
    [InlineData("/\\evil.com", "https", TenantHost, true, RootDomain, null)]
    [InlineData("/\t/evil.com", "https", TenantHost, true, RootDomain, null)]
    [InlineData("\n//evil.com", "https", TenantHost, true, RootDomain, null)]
    [InlineData("https://other.myapp.com/dashboard", "https", TenantHost, true, RootDomain, null)]
    [InlineData("https://myapp.com.evil.com/dashboard", "https", TenantHost, true, RootDomain, null)]
    [InlineData("http://acme.myapp.com/dashboard", "https", TenantHost, true, RootDomain, null)]
    [InlineData("javascript:alert(1)", "https", TenantHost, true, RootDomain, null)]
    [InlineData("https://myapp.com/dashboard", "https", "acme.example.com", true, "", null)]
    [InlineData(" /settings ", "https", TenantHost, true, RootDomain, "https://acme.myapp.com/settings")]
    public void ValidateReturnUrl_AllowsOnlyTrustedHosts(
        string? returnUrl,
        string scheme,
        string host,
        bool appLevelEnabled,
        string rootDomain,
        string? expected)
    {
        Assert.Equal(expected, TenantUrlUtils.ValidateReturnUrl(returnUrl, scheme, host, TenantName, appLevelEnabled, rootDomain));
    }

    [Fact]
    public void ValidateReturnUrl_WithoutTenantName_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => TenantUrlUtils.ValidateReturnUrl("/settings", "https", TenantHost, string.Empty, true, RootDomain));
    }
}
