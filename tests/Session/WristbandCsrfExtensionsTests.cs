using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandCsrfExtensionsTests
{
    [Fact]
    public void AddWristbandCsrfProtection_EnablesCsrfProtection()
    {
        var services = new ServiceCollection();
        services.AddWristbandCsrfProtection();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<WristbandCsrfOptions>>();

        Assert.True(options.Value.EnableCsrfProtection);
    }

    [Fact]
    public void AddWristbandCsrfProtection_UsesDefaultValues_WhenNoConfigureProvided()
    {
        var services = new ServiceCollection();
        services.AddWristbandCsrfProtection();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<WristbandCsrfOptions>>();

        Assert.True(options.Value.EnableCsrfProtection);
        Assert.Equal("CSRF-TOKEN", options.Value.CsrfCookieName);
        Assert.Equal("X-CSRF-TOKEN", options.Value.CsrfHeaderName);
        Assert.Null(options.Value.CsrfCookieDomain);
    }

    [Fact]
    public void AddWristbandCsrfProtection_AppliesCustomConfiguration()
    {
        var services = new ServiceCollection();
        services.AddWristbandCsrfProtection(options =>
        {
            options.CsrfCookieName = "MY-CSRF";
            options.CsrfHeaderName = "X-MY-CSRF";
            options.CsrfCookieDomain = ".example.com";
        });

        var provider = services.BuildServiceProvider();
        var csrfOptions = provider.GetRequiredService<IOptions<WristbandCsrfOptions>>();

        Assert.True(csrfOptions.Value.EnableCsrfProtection);
        Assert.Equal("MY-CSRF", csrfOptions.Value.CsrfCookieName);
        Assert.Equal("X-MY-CSRF", csrfOptions.Value.CsrfHeaderName);
        Assert.Equal(".example.com", csrfOptions.Value.CsrfCookieDomain);
    }

    [Fact]
    public void AddWristbandCsrfProtection_ReturnsServiceCollection()
    {
        var services = new ServiceCollection();
        var result = services.AddWristbandCsrfProtection();
        Assert.Same(services, result);
    }

    [Fact]
    public void AddWristbandCsrfProtection_CanBeCalledMultipleTimes()
    {
        var services = new ServiceCollection();
        services.AddWristbandCsrfProtection(options => options.CsrfCookieName = "FIRST");
        services.AddWristbandCsrfProtection(options => options.CsrfCookieName = "SECOND");

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<WristbandCsrfOptions>>();

        Assert.Equal("SECOND", options.Value.CsrfCookieName);
    }

    [Fact]
    public void AddWristbandCsrfProtection_ConfigureCanModifyEnableCsrfProtection()
    {
        var services = new ServiceCollection();
        services.AddWristbandCsrfProtection(options =>
        {
            options.EnableCsrfProtection = false;
        });

        var provider = services.BuildServiceProvider();
        var csrfOptions = provider.GetRequiredService<IOptions<WristbandCsrfOptions>>();

        Assert.False(csrfOptions.Value.EnableCsrfProtection);
    }
}
