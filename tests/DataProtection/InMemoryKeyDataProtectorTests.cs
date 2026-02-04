using System.Security.Cryptography;
using System.Text;

using Wristband.AspNet.Auth;

namespace Wristband.AspNet.Tests.DataProtection;

public class InMemoryKeyDataProtectorTests
{
    private const string TestSecret = "test-secret-key-min-32-chars-long-1234567890";
    private const string TestPurpose = "test-purpose";

    [Fact]
    public void Protect_WithValidPlaintext_ReturnsEncryptedData()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        var protectedData = protector.Protect(plaintext);

        Assert.NotNull(protectedData);
        Assert.True(protectedData.Length > plaintext.Length);
    }

    [Fact]
    public void Protect_WithNullPlaintext_ThrowsArgumentException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);

        var exception = Assert.Throws<ArgumentException>(() => protector.Protect(null!));

        Assert.Equal("plaintext", exception.ParamName);
    }

    [Fact]
    public void Protect_WithEmptyPlaintext_ThrowsArgumentException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);

        var exception = Assert.Throws<ArgumentException>(() => protector.Protect([]));

        Assert.Equal("plaintext", exception.ParamName);
    }

    [Fact]
    public void Unprotect_WithValidProtectedData_ReturnsOriginalPlaintext()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protectedData = protector.Protect(plaintext);

        var unprotected = protector.Unprotect(protectedData);

        Assert.Equal(plaintext, unprotected);
    }

    [Fact]
    public void Unprotect_WithTamperedData_ThrowsCryptographicException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protectedData = protector.Protect(plaintext);

        protectedData[protectedData.Length - 1] ^= 0xFF;

        Assert.Throws<CryptographicException>(() => protector.Unprotect(protectedData));
    }

    [Fact]
    public void Unprotect_WithNullData_ThrowsCryptographicException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);

        Assert.Throws<CryptographicException>(() => protector.Unprotect(null!));
    }

    [Fact]
    public void Unprotect_WithTooShortData_ThrowsCryptographicException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var tooShort = new byte[36];

        Assert.Throws<CryptographicException>(() => protector.Unprotect(tooShort));
    }

    [Fact]
    public void Unprotect_WithUnsupportedVersion_ThrowsCryptographicException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protectedData = protector.Protect(plaintext);

        protectedData[0] = 99;

        var exception = Assert.Throws<CryptographicException>(() => protector.Unprotect(protectedData));

        Assert.Contains("Unsupported data protection version", exception.Message);
    }

    [Fact]
    public void Unprotect_WithFutureTimestamp_ThrowsCryptographicException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protectedData = protector.Protect(plaintext);

        var futureTimestamp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var timestampBytes = BitConverter.GetBytes(futureTimestamp);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(timestampBytes);
        }
        Buffer.BlockCopy(timestampBytes, 0, protectedData, 1, 8);

        var exception = Assert.Throws<CryptographicException>(() => protector.Unprotect(protectedData));

        Assert.Contains("timestamp is invalid", exception.Message);
    }

    [Fact]
    public void Unprotect_WithWrongSecret_ThrowsCryptographicException()
    {
        var protector1 = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var protector2 = new InMemoryKeyDataProtector(TestPurpose, ["different-secret-key-min-32-chars-long-xyz"]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protectedData = protector1.Protect(plaintext);

        var exception = Assert.Throws<CryptographicException>(() => protector2.Unprotect(protectedData));

        Assert.Contains("Failed to decrypt data with any of the provided secrets", exception.Message);
    }

    [Fact]
    public void SecretRotation_OldSecretCanDecrypt()
    {
        var oldSecret = "old-secret-key-min-32-chars-long-1234567890";
        var newSecret = "new-secret-key-min-32-chars-long-1234567890";

        var protectorOld = new InMemoryKeyDataProtector(TestPurpose, [oldSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protectedData = protectorOld.Protect(plaintext);

        var protectorRotated = new InMemoryKeyDataProtector(TestPurpose, [newSecret, oldSecret]);

        var unprotected = protectorRotated.Unprotect(protectedData);

        Assert.Equal(plaintext, unprotected);
    }

    [Fact]
    public void SecretRotation_NewSecretUsedForEncryption()
    {
        var oldSecret = "old-secret-key-min-32-chars-long-1234567890";
        var newSecret = "new-secret-key-min-32-chars-long-1234567890";

        var protectorRotated = new InMemoryKeyDataProtector(TestPurpose, [newSecret, oldSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protectedData = protectorRotated.Protect(plaintext);

        var protectorNew = new InMemoryKeyDataProtector(TestPurpose, [newSecret]);

        var unprotected = protectorNew.Unprotect(protectedData);

        Assert.Equal(plaintext, unprotected);
    }

    [Fact]
    public void CreateProtector_WithValidPurpose_ReturnsNewProtector()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);

        var childProtector = protector.CreateProtector("child-purpose");

        Assert.NotNull(childProtector);
        Assert.IsType<InMemoryKeyDataProtector>(childProtector);
    }

    [Fact]
    public void CreateProtector_WithNullPurpose_ThrowsArgumentException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);

        var exception = Assert.Throws<ArgumentException>(() => protector.CreateProtector(null!));

        Assert.Equal("purpose", exception.ParamName);
    }

    [Fact]
    public void CreateProtector_WithEmptyPurpose_ThrowsArgumentException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);

        var exception = Assert.Throws<ArgumentException>(() => protector.CreateProtector(string.Empty));

        Assert.Equal("purpose", exception.ParamName);
    }

    [Fact]
    public void CreateProtector_WithWhitespacePurpose_ThrowsArgumentException()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);

        var exception = Assert.Throws<ArgumentException>(() => protector.CreateProtector("   "));

        Assert.Equal("purpose", exception.ParamName);
    }

    [Fact]
    public void DifferentPurposes_ProduceDifferentCiphertext()
    {
        var protector1 = new InMemoryKeyDataProtector("purpose1", [TestSecret]);
        var protector2 = new InMemoryKeyDataProtector("purpose2", [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        var protected1 = protector1.Protect(plaintext);
        var protected2 = protector2.Protect(plaintext);

        Assert.NotEqual(protected1, protected2);
    }

    [Fact]
    public void DifferentPurposes_CannotDecryptEachOther()
    {
        var protector1 = new InMemoryKeyDataProtector("purpose1", [TestSecret]);
        var protector2 = new InMemoryKeyDataProtector("purpose2", [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var protected1 = protector1.Protect(plaintext);

        Assert.Throws<CryptographicException>(() => protector2.Unprotect(protected1));
    }

    [Fact]
    public void HierarchicalPurposes_ProduceDifferentKeys()
    {
        var protector = new InMemoryKeyDataProtector("parent", [TestSecret]);
        var childProtector = protector.CreateProtector("child");
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        var protectedParent = protector.Protect(plaintext);
        var protectedChild = childProtector.Protect(plaintext);

        Assert.NotEqual(protectedParent, protectedChild);
    }

    [Fact]
    public void ProtectUnprotect_RoundTrip_PreservesData()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        byte[] testData = [0, 1, 2, 3, 255, 254, 253];

        var protectedData = protector.Protect(testData);
        var unprotected = protector.Unprotect(protectedData);

        Assert.Equal(testData, unprotected);
    }

    [Fact]
    public void Protect_ProducesDifferentCiphertextEachTime()
    {
        var protector = new InMemoryKeyDataProtector(TestPurpose, [TestSecret]);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        var protected1 = protector.Protect(plaintext);
        var protected2 = protector.Protect(plaintext);

        Assert.NotEqual(protected1, protected2);
    }
}
