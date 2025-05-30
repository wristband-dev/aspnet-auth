using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandAuthServiceFactoryTests
{
    private IOptions<WristbandAuthConfig> CreateValidOptions()
    {
        return Options.Create(new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback",
            WristbandApplicationVanityDomain = "example.com",
        });
    }

    [Fact]
    public void GetService_WithValidName_ReturnsCorrectService()
    {
        var serviceA = new NamedWristbandAuthService("ServiceA", CreateValidOptions());
        var serviceB = new NamedWristbandAuthService("ServiceB", CreateValidOptions());

        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(serviceA);
        serviceCollection.AddSingleton(serviceB);
        var serviceProvider = serviceCollection.BuildServiceProvider();

        var factory = new WristbandAuthServiceFactory(serviceProvider);

        var result = factory.GetService("ServiceA");

        Assert.Same(serviceA, result);
    }

    [Fact]
    public void GetService_WithInvalidName_ThrowsException()
    {
        var serviceA = new NamedWristbandAuthService("ServiceA", CreateValidOptions());

        var serviceCollection = new ServiceCollection();
        serviceCollection.AddSingleton(serviceA);
        var serviceProvider = serviceCollection.BuildServiceProvider();

        var factory = new WristbandAuthServiceFactory(serviceProvider);

        var exception = Assert.Throws<InvalidOperationException>(() => factory.GetService("NonExistentService"));

        Assert.Contains("No auth service registered with name 'NonExistentService'", exception.Message);
    }

    [Fact]
    public void GetService_WithNoServices_ThrowsException()
    {
        var serviceCollection = new ServiceCollection();
        var serviceProvider = serviceCollection.BuildServiceProvider();

        var factory = new WristbandAuthServiceFactory(serviceProvider);

        var exception = Assert.Throws<InvalidOperationException>(() => factory.GetService("AnyName"));

        Assert.Contains("No auth service registered with name 'AnyName'", exception.Message);
    }

    [Fact]
    public void Constructor_WithNullServiceProvider_ThrowsException()
    {
        Assert.Throws<ArgumentNullException>(() => new WristbandAuthServiceFactory(null!));
    }
}
