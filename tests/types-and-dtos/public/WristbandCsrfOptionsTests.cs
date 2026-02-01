
namespace Wristband.AspNet.Auth.Tests;

public class WristbandCsrfOptionsTests
{
    [Fact]
    public void DefaultValues_AreSetCorrectly()
    {
        var options = new WristbandCsrfOptions();

        Assert.False(options.EnableCsrfProtection);
        Assert.Equal("CSRF-TOKEN", options.CsrfCookieName);
        Assert.Equal("X-CSRF-TOKEN", options.CsrfHeaderName);
        Assert.Null(options.CsrfCookieDomain);
    }

    [Fact]
    public void EnableCsrfProtection_CanBeSet()
    {
        var options = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true
        };
        Assert.True(options.EnableCsrfProtection);
    }

    [Fact]
    public void CsrfCookieName_CanBeCustomized()
    {
        var options = new WristbandCsrfOptions
        {
            CsrfCookieName = "MY-CUSTOM-CSRF"
        };
        Assert.Equal("MY-CUSTOM-CSRF", options.CsrfCookieName);
    }

    [Fact]
    public void CsrfHeaderName_CanBeCustomized()
    {
        var options = new WristbandCsrfOptions
        {
            CsrfHeaderName = "X-MY-CSRF-HEADER"
        };
        Assert.Equal("X-MY-CSRF-HEADER", options.CsrfHeaderName);
    }

    [Fact]
    public void CsrfCookieDomain_CanBeSet()
    {
        var options = new WristbandCsrfOptions
        {
            CsrfCookieDomain = ".example.com"
        };
        Assert.Equal(".example.com", options.CsrfCookieDomain);
    }

    [Fact]
    public void AllProperties_CanBeSetTogether()
    {
        var options = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CUSTOM-CSRF",
            CsrfHeaderName = "X-CUSTOM-CSRF",
            CsrfCookieDomain = ".myapp.com"
        };
        Assert.True(options.EnableCsrfProtection);
        Assert.Equal("CUSTOM-CSRF", options.CsrfCookieName);
        Assert.Equal("X-CUSTOM-CSRF", options.CsrfHeaderName);
        Assert.Equal(".myapp.com", options.CsrfCookieDomain);
    }
}
