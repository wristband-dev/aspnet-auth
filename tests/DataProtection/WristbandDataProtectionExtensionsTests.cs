using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

using Wristband.AspNet.Auth;

namespace Wristband.AspNet.Tests.DataProtection;

public class WristbandDataProtectionExtensionsTests
{
    private const string ValidSecret = "test-secret-key-min-32-chars-long-1234567890";

    [Fact]
    public void AddInMemoryKeyDataProtection_WithSingleSecret_RegistersProvider()
    {
        var services = new ServiceCollection();

        services.AddInMemoryKeyDataProtection(ValidSecret);

        var serviceProvider = services.BuildServiceProvider();
        var provider = serviceProvider.GetService<IDataProtectionProvider>();
        Assert.NotNull(provider);
        Assert.IsType<InMemoryKeyDataProtectionProvider>(provider);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithMultipleSecrets_RegistersProvider()
    {
        var services = new ServiceCollection();
        var secrets = new[]
        {
            "new-secret-key-min-32-chars-long-1234567890",
            "old-secret-key-min-32-chars-long-1234567890"
        };

        services.AddInMemoryKeyDataProtection(secrets);

        var serviceProvider = services.BuildServiceProvider();
        var provider = serviceProvider.GetService<IDataProtectionProvider>();
        Assert.NotNull(provider);
        Assert.IsType<InMemoryKeyDataProtectionProvider>(provider);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithNullSecret_ThrowsArgumentException()
    {
        var services = new ServiceCollection();

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection((string)null!));

        Assert.Equal("secrets", exception.ParamName);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithNullSecretsArray_ThrowsArgumentException()
    {
        var services = new ServiceCollection();

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection((string[])null!));

        Assert.Equal("secrets", exception.ParamName);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithEmptySecretsArray_ThrowsArgumentException()
    {
        var services = new ServiceCollection();

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection([]));

        Assert.Equal("secrets", exception.ParamName);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithMoreThan3Secrets_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        var secrets = new[]
        {
            "secret1-key-min-32-chars-long-1234567890",
            "secret2-key-min-32-chars-long-1234567890",
            "secret3-key-min-32-chars-long-1234567890",
            "secret4-key-min-32-chars-long-1234567890"
        };

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection(secrets));

        Assert.Equal("secrets", exception.ParamName);
        Assert.Contains("Maximum 3 secrets", exception.Message);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithNullSecretInArray_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        var secrets = new[] { ValidSecret, null! };

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection(secrets));

        Assert.Equal("secrets", exception.ParamName);
        Assert.Contains("cannot be null or whitespace", exception.Message);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithEmptySecretInArray_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        var secrets = new[] { ValidSecret, string.Empty };

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection(secrets));

        Assert.Equal("secrets", exception.ParamName);
        Assert.Contains("cannot be null or whitespace", exception.Message);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithWhitespaceSecretInArray_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        var secrets = new[] { ValidSecret, "   " };

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection(secrets));

        Assert.Equal("secrets", exception.ParamName);
        Assert.Contains("cannot be null or whitespace", exception.Message);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithTooShortSecret_ThrowsArgumentException()
    {
        var services = new ServiceCollection();
        var secrets = new[] { "too-short" };

        var exception = Assert.Throws<ArgumentException>(() => services.AddInMemoryKeyDataProtection(secrets));

        Assert.Equal("secrets", exception.ParamName);
        Assert.Contains("at least 32 characters", exception.Message);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_CalledTwice_UsesFirstRegistration()
    {
        var services = new ServiceCollection();
        var secret1 = "first-secret-key-min-32-chars-long-1234567890";
        var secret2 = "second-secret-key-min-32-chars-long-1234567890";

        services.AddInMemoryKeyDataProtection(secret1);
        services.AddInMemoryKeyDataProtection(secret2);

        var serviceProvider = services.BuildServiceProvider();
        var provider = serviceProvider.GetService<IDataProtectionProvider>();
        Assert.NotNull(provider);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_WithExistingProvider_DoesNotReplace()
    {
        var services = new ServiceCollection();
        var mockProvider = new MockDataProtectionProvider();
        services.AddSingleton<IDataProtectionProvider>(mockProvider);

        services.AddInMemoryKeyDataProtection(ValidSecret);

        var serviceProvider = services.BuildServiceProvider();
        var provider = serviceProvider.GetService<IDataProtectionProvider>();
        Assert.Same(mockProvider, provider);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_ReturnsServiceCollection()
    {
        var services = new ServiceCollection();

        var result = services.AddInMemoryKeyDataProtection(ValidSecret);

        Assert.Same(services, result);
    }

    [Fact]
    public void AddInMemoryKeyDataProtection_ProviderCanCreateProtectors()
    {
        var services = new ServiceCollection();
        services.AddInMemoryKeyDataProtection(ValidSecret);
        var serviceProvider = services.BuildServiceProvider();
        var provider = serviceProvider.GetRequiredService<IDataProtectionProvider>();

        var protector = provider.CreateProtector("test-purpose");

        Assert.NotNull(protector);
    }

    private class MockDataProtectionProvider : IDataProtectionProvider
    {
        public IDataProtector CreateProtector(string purpose)
        {
            throw new NotImplementedException();
        }
    }
}
