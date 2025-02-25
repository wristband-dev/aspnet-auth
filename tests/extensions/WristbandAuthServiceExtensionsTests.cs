using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandServiceExtensionsTests
{
    [Fact]
    public void AddWristbandAuth_WithConfiguration_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                {"WristbandAuthConfig:ClientId", "test-client"},
                {"WristbandAuthConfig:ClientSecret", "test-secret"},
                {"WristbandAuthConfig:LoginStateSecret", "this-is-a-secret-that-is-at-least-32-chars"},
                {"WristbandAuthConfig:LoginUrl", "https://login.url"},
                {"WristbandAuthConfig:RedirectUri", "https://redirect.uri"},
                {"WristbandAuthConfig:WristbandApplicationDomain", "wristband.domain"}
            })
            .Build();

        services.AddWristbandAuth(configuration);

        var serviceProvider = services.BuildServiceProvider();
        var authConfig = serviceProvider.GetService<IOptions<WristbandAuthConfig>>();
        Assert.NotNull(authConfig);
        Assert.Equal("test-client", authConfig.Value.ClientId);
        Assert.Equal("test-secret", authConfig.Value.ClientSecret);
    }

    [Fact]
    public void AddWristbandAuth_WithConfiguration_CustomSectionName_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                {"CustomSection:ClientId", "test-client"},
                {"CustomSection:ClientSecret", "test-secret"},
                {"CustomSection:LoginStateSecret", "this-is-a-secret-that-is-at-least-32-chars"},
                {"CustomSection:LoginUrl", "https://login.url"},
                {"CustomSection:RedirectUri", "https://redirect.uri"},
                {"CustomSection:WristbandApplicationDomain", "wristband.domain"}
            })
            .Build();

        services.AddWristbandAuth(configuration, "CustomSection");

        var serviceProvider = services.BuildServiceProvider();
        var authConfig = serviceProvider.GetService<IOptions<WristbandAuthConfig>>();
        Assert.NotNull(authConfig);
        Assert.Equal("test-client", authConfig.Value.ClientId);
        Assert.Equal("test-secret", authConfig.Value.ClientSecret);
    }

    [Fact]
    public void AddWristbandAuth_WithDirectConfiguration_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        services.AddWristbandAuth(options =>
        {
            options.ClientId = "direct-client";
            options.ClientSecret = "direct-secret";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationDomain = "wristband.domain";
        });

        var serviceProvider = services.BuildServiceProvider();
        var authConfig = serviceProvider.GetService<IOptions<WristbandAuthConfig>>();
        Assert.NotNull(authConfig);
        Assert.Equal("direct-client", authConfig.Value.ClientId);
        Assert.Equal("direct-secret", authConfig.Value.ClientSecret);

        var authService = serviceProvider.GetService<IWristbandAuthService>();
        Assert.NotNull(authService);
        Assert.IsType<WristbandAuthService>(authService);
    }

    [Fact]
    public void AddWristbandAuth_ServicesAreRegisteredAsScoped()
    {
        var services = new ServiceCollection();

        services.AddWristbandAuth(options =>
        {
            options.ClientId = "test";
            options.ClientSecret = "test";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationDomain = "wristband.domain";
        });

        var registration = services.FirstOrDefault(sd => sd.ServiceType == typeof(IWristbandAuthService));
        Assert.NotNull(registration);
        Assert.Equal(ServiceLifetime.Scoped, registration.Lifetime);
    }

    // Null check tests remain the same as they're testing edge cases
    [Fact]
    public void AddWristbandAuth_WithNullConfiguration_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        IConfiguration configuration = null!;

        var exception = Assert.Throws<ArgumentNullException>(() => services.AddWristbandAuth(configuration));
        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void AddWristbandAuth_WithNullConfigureOptions_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Action<WristbandAuthConfig> configureOptions = null!;

        var exception = Assert.Throws<ArgumentNullException>(() => services.AddWristbandAuth(configureOptions));
        Assert.Equal("configureOptions", exception.ParamName);
    }

    [Fact]
    public void AddWristbandAuth_WithNullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        var configuration = new ConfigurationBuilder().Build();

        var exception = Assert.Throws<ArgumentNullException>(() => services.AddWristbandAuth(configuration));
        Assert.Equal("services", exception.ParamName);
    }
}
