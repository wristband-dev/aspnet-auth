using Microsoft.Extensions.Options;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class NamedWristbandAuthServiceTests
{
    private WristbandAuthConfig CreateValidConfig()
    {
        return new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32), // At least 32 characters
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback",
            WristbandApplicationDomain = "example.com",
            RootDomain = "example.com",
            UseTenantSubdomains = false
        };
    }

    [Fact]
    public void Constructor_SetsNameProperly()
    {
        var expectedName = "clientA";
        var optionsMock = new Mock<IOptions<WristbandAuthConfig>>();
        optionsMock.Setup(o => o.Value).Returns(CreateValidConfig());

        var service = new NamedWristbandAuthService(expectedName, optionsMock.Object);

        Assert.Equal(expectedName, service.Name);
    }

    [Fact]
    public void Constructor_AllowsNullHttpClientFactory()
    {
        var options = Options.Create(CreateValidConfig());

        var service = new NamedWristbandAuthService("clientX", options, null);

        Assert.NotNull(service);
    }

    [Fact]
    public void DifferentInstances_HaveDifferentNames()
    {
        var options = Options.Create(CreateValidConfig());

        var serviceA = new NamedWristbandAuthService("alpha", options);
        var serviceB = new NamedWristbandAuthService("beta", options);

        Assert.NotEqual(serviceA.Name, serviceB.Name);
    }
}
