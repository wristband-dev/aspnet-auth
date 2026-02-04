using Wristband.AspNet.Auth;

namespace Wristband.AspNet.Tests.DataProtection;

public class InMemoryKeyDataProtectionProviderTests
{
    [Fact]
    public void Constructor_StoresSecrets()
    {
        var secrets = new[] { "test-secret-key-min-32-chars-long-1234567890" };

        var provider = new InMemoryKeyDataProtectionProvider(secrets);

        Assert.NotNull(provider);
    }

    [Fact]
    public void CreateProtector_ReturnsSameProtectorForSamePurpose()
    {
        var secrets = new[] { "test-secret-key-min-32-chars-long-1234567890" };
        var provider = new InMemoryKeyDataProtectionProvider(secrets);

        var protector1 = provider.CreateProtector("test-purpose");
        var protector2 = provider.CreateProtector("test-purpose");

        Assert.NotSame(protector1, protector2);
    }

    [Fact]
    public void CreateProtector_ReturnsDifferentProtectorsForDifferentPurposes()
    {
        var secrets = new[] { "test-secret-key-min-32-chars-long-1234567890" };
        var provider = new InMemoryKeyDataProtectionProvider(secrets);

        var protector1 = provider.CreateProtector("purpose1");
        var protector2 = provider.CreateProtector("purpose2");

        Assert.NotSame(protector1, protector2);
    }

    [Fact]
    public void CreateProtector_ReturnsInMemoryKeyDataProtector()
    {
        var secrets = new[] { "test-secret-key-min-32-chars-long-1234567890" };
        var provider = new InMemoryKeyDataProtectionProvider(secrets);

        var protector = provider.CreateProtector("test-purpose");

        Assert.IsType<InMemoryKeyDataProtector>(protector);
    }

    [Fact]
    public void CreateProtector_WithMultipleSecrets_CreatesProtectorWithAllSecrets()
    {
        var secrets = new[]
        {
            "new-secret-key-min-32-chars-long-1234567890",
            "old-secret-key-min-32-chars-long-1234567890"
        };
        var provider = new InMemoryKeyDataProtectionProvider(secrets);

        var protector = provider.CreateProtector("test-purpose");

        Assert.NotNull(protector);
        Assert.IsType<InMemoryKeyDataProtector>(protector);
    }
}
