using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandServiceExtensionsTests
{
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
            options.WristbandApplicationVanityDomain = "wristband.domain";
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
    public void AddWristbandAuth_WithDirectConfiguration_AndHttpClientFactory_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        var mockFactory = new Mock<IHttpClientFactory>();

        services.AddWristbandAuth(options =>
        {
            options.ClientId = "direct-client";
            options.ClientSecret = "direct-secret";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationVanityDomain = "wristband.domain";
        }, mockFactory.Object);

        var serviceProvider = services.BuildServiceProvider();
        var authService = serviceProvider.GetService<IWristbandAuthService>();
        Assert.NotNull(authService);
        Assert.IsType<WristbandAuthService>(authService);
    }

    [Fact]
    public void AddWristbandAuth_WithNamedService_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        services.AddWristbandAuth("auth01", options =>
        {
            options.ClientId = "named-client";
            options.ClientSecret = "named-secret";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationVanityDomain = "wristband.domain";
        });

        var serviceProvider = services.BuildServiceProvider();

        // Check if the options are registered correctly
        var optionsMonitor = serviceProvider.GetService<IOptionsMonitor<WristbandAuthConfig>>();
        Assert.NotNull(optionsMonitor);
        var namedOptions = optionsMonitor.Get("auth01");
        Assert.Equal("named-client", namedOptions.ClientId);
        Assert.Equal("named-secret", namedOptions.ClientSecret);

        // Check if the named service is registered
        var namedServices = serviceProvider.GetServices<NamedWristbandAuthService>();
        Assert.NotEmpty(namedServices);
        var namedService = namedServices.FirstOrDefault(s => s.Name == "auth01");
        Assert.NotNull(namedService);
        Assert.Equal("auth01", namedService.Name);

        // Check if the factory is registered
        var factory = serviceProvider.GetService<WristbandAuthServiceFactory>();
        Assert.NotNull(factory);
    }

    [Fact]
    public void AddWristbandAuth_WithNamedService_AndHttpClientFactory_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        var mockFactory = new Mock<IHttpClientFactory>();

        services.AddWristbandAuth("auth01", options =>
        {
            options.ClientId = "named-client";
            options.ClientSecret = "named-secret";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationVanityDomain = "wristband.domain";
        }, mockFactory.Object);

        var serviceProvider = services.BuildServiceProvider();

        // Check if the options are registered correctly
        var optionsMonitor = serviceProvider.GetService<IOptionsMonitor<WristbandAuthConfig>>();
        Assert.NotNull(optionsMonitor);
        var namedOptions = optionsMonitor.Get("auth01");
        Assert.Equal("named-client", namedOptions.ClientId);
        Assert.Equal("named-secret", namedOptions.ClientSecret);

        // Check if the named service is registered
        var namedServices = serviceProvider.GetServices<NamedWristbandAuthService>();
        Assert.NotEmpty(namedServices);
        var namedService = namedServices.FirstOrDefault(s => s.Name == "auth01");
        Assert.NotNull(namedService);
        Assert.Equal("auth01", namedService.Name);
    }

    [Fact]
    public void WristbandAuthServiceFactory_GetService_ReturnsCorrectNamedService()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        // Add multiple named services
        services.AddWristbandAuth("auth01", options =>
        {
            options.ClientId = "client01";
            options.ClientSecret = "secret01";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationVanityDomain = "wristband.domain";
        });

        services.AddWristbandAuth("auth02", options =>
        {
            options.ClientId = "client02";
            options.ClientSecret = "secret02";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationVanityDomain = "wristband.domain";
        });

        var serviceProvider = services.BuildServiceProvider();
        var factory = serviceProvider.GetService<WristbandAuthServiceFactory>();
        Assert.NotNull(factory);

        // Get services by name and verify they're correct
        var auth01Service = factory.GetService("auth01");
        Assert.NotNull(auth01Service);
        Assert.IsType<NamedWristbandAuthService>(auth01Service);
        var namedService01 = auth01Service as NamedWristbandAuthService;
        Assert.Equal("auth01", namedService01?.Name);

        var auth02Service = factory.GetService("auth02");
        Assert.NotNull(auth02Service);
        Assert.IsType<NamedWristbandAuthService>(auth02Service);
        var namedService02 = auth02Service as NamedWristbandAuthService;
        Assert.Equal("auth02", namedService02?.Name);
    }

    [Fact]
    public void WristbandAuthServiceFactory_GetService_ThrowsException_WhenNameNotFound()
    {
        var services = new ServiceCollection();
        services.AddOptions();

        // Add a named service
        services.AddWristbandAuth("auth01", options =>
        {
            options.ClientId = "client01";
            options.ClientSecret = "secret01";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationVanityDomain = "wristband.domain";
        });

        var serviceProvider = services.BuildServiceProvider();
        var factory = serviceProvider.GetService<WristbandAuthServiceFactory>();
        Assert.NotNull(factory);

        // Try to get a non-existent service
        var exception = Assert.Throws<InvalidOperationException>(() => factory.GetService("non-existent"));
        Assert.Contains("No auth service registered with name 'non-existent'", exception.Message);
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
            options.WristbandApplicationVanityDomain = "wristband.domain";
        });

        var registration = services.FirstOrDefault(sd => sd.ServiceType == typeof(IWristbandAuthService));
        Assert.NotNull(registration);
        Assert.Equal(ServiceLifetime.Singleton, registration.Lifetime);
    }

    [Fact]
    public void AddWristbandAuth_NamedServices_AreRegisteredAsSingleton()
    {
        var services = new ServiceCollection();

        services.AddWristbandAuth("auth01", options =>
        {
            options.ClientId = "test";
            options.ClientSecret = "test";
            options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
            options.LoginUrl = "https://login.url";
            options.RedirectUri = "https://redirect.uri";
            options.WristbandApplicationVanityDomain = "wristband.domain";
        });

        var registration = services.FirstOrDefault(sd => sd.ServiceType == typeof(NamedWristbandAuthService));
        Assert.NotNull(registration);
        Assert.Equal(ServiceLifetime.Singleton, registration.Lifetime);
    }

    // Null check tests for the named service registration
    [Fact]
    public void AddWristbandAuth_WithNullName_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        string name = null!;

        var exception = Assert.Throws<ArgumentNullException>(() => services.AddWristbandAuth(
            name,
            options => { }
        ));
        Assert.Equal("name", exception.ParamName);
    }

    [Fact]
    public void AddWristbandAuth_WithNamedService_NullConfigureOptions_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Action<WristbandAuthConfig> configureOptions = null!;

        var exception = Assert.Throws<ArgumentNullException>(() => services.AddWristbandAuth(
            "auth01",
            configureOptions
        ));
        Assert.Equal("configureOptions", exception.ParamName);
    }

    [Fact]
    public void AddWristbandAuth_WithNamedService_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;

        var exception = Assert.Throws<ArgumentNullException>(() => services.AddWristbandAuth(
            "auth01",
            options => { }
        ));
        Assert.Equal("services", exception.ParamName);
    }
}
