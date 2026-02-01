using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests;

public class TokenResponseTests
{
    // ////////////////////////////////////
    //  CONSTRUCTOR/INITIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_WithValidProperties_CreatesInstance()
    {
        var expiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds();
        var response = new TokenResponse
        {
            AccessToken = "test_access_token",
            ExpiresAt = expiresAt
        };

        Assert.NotNull(response);
        Assert.Equal("test_access_token", response.AccessToken);
        Assert.Equal(expiresAt, response.ExpiresAt);
    }

    [Fact]
    public void Constructor_WithMinimalData_CreatesInstance()
    {
        var response = new TokenResponse
        {
            AccessToken = "a",
            ExpiresAt = 0
        };

        Assert.Equal("a", response.AccessToken);
        Assert.Equal(0, response.ExpiresAt);
    }

    [Fact]
    public void Constructor_WithLongToken_CreatesInstance()
    {
        var longToken = new string('x', 1000);
        var response = new TokenResponse
        {
            AccessToken = longToken,
            ExpiresAt = 1234567890000
        };

        Assert.Equal(longToken, response.AccessToken);
    }

    // ////////////////////////////////////
    //  JSON SERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Serialize_WithValidData_ProducesCorrectJson()
    {
        var expiresAt = 1234567890000L;
        var response = new TokenResponse
        {
            AccessToken = "test_access_token",
            ExpiresAt = expiresAt
        };

        var json = JsonSerializer.Serialize(response);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("test_access_token", root.GetProperty("accessToken").GetString());
        Assert.Equal(expiresAt, root.GetProperty("expiresAt").GetInt64());
    }

    [Fact]
    public void Serialize_UsesCorrectJsonPropertyNames()
    {
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = 1234567890000
        };

        var json = JsonSerializer.Serialize(response);

        // Should use camelCase from JsonPropertyName attributes
        Assert.Contains("\"accessToken\":", json);
        Assert.Contains("\"expiresAt\":", json);

        // Should NOT use PascalCase C# property names
        Assert.DoesNotContain("\"AccessToken\":", json);
        Assert.DoesNotContain("\"ExpiresAt\":", json);
    }

    [Fact]
    public void Serialize_MatchesWristbandFrontendSDKFormat()
    {
        // This format must match what Wristband frontend SDKs expect
        var response = new TokenResponse
        {
            AccessToken = "abc123",
            ExpiresAt = 1234567890000
        };

        var json = JsonSerializer.Serialize(response);

        // Verify expected structure
        Assert.Contains("\"accessToken\":\"abc123\"", json);
        Assert.Contains("\"expiresAt\":1234567890000", json);
    }

    // ////////////////////////////////////
    //  JSON DESERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Deserialize_WithValidJson_CreatesInstance()
    {
        var json = @"{
            ""accessToken"": ""test_access_token"",
            ""expiresAt"": 1234567890000
        }";

        var response = JsonSerializer.Deserialize<TokenResponse>(json);

        Assert.NotNull(response);
        Assert.Equal("test_access_token", response.AccessToken);
        Assert.Equal(1234567890000, response.ExpiresAt);
    }

    [Fact]
    public void Deserialize_WithMissingAccessToken_ThrowsJsonException()
    {
        var json = @"{
            ""expiresAt"": 1234567890000
        }";

        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<TokenResponse>(json));

        Assert.Contains("accessToken", exception.Message);
    }

    [Fact]
    public void Deserialize_WithMissingExpiresAt_ThrowsJsonException()
    {
        var json = @"{
            ""accessToken"": ""test_token""
        }";

        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<TokenResponse>(json));

        Assert.Contains("expiresAt", exception.Message);
    }

    // ////////////////////////////////////
    //  PROPERTY BEHAVIOR TESTS
    // ////////////////////////////////////

    [Fact]
    public void Properties_AreInitOnly_CannotBeModifiedAfterConstruction()
    {
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = 1234567890000
        };

        // This should not compile - init-only properties
        // response.AccessToken = "different";
        // response.ExpiresAt = 9999999999999;

        Assert.Equal("test_token", response.AccessToken);
        Assert.Equal(1234567890000, response.ExpiresAt);
    }

    // ////////////////////////////////////
    //  EXPIRESAI TIMESTAMP TESTS
    // ////////////////////////////////////

    [Fact]
    public void ExpiresAt_WithCurrentTime_StoresCorrectly()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = now
        };

        Assert.Equal(now, response.ExpiresAt);
    }

    [Fact]
    public void ExpiresAt_WithFutureTime_StoresCorrectly()
    {
        var future = DateTimeOffset.UtcNow.AddHours(24).ToUnixTimeMilliseconds();
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = future
        };

        Assert.Equal(future, response.ExpiresAt);
    }

    [Fact]
    public void ExpiresAt_WithPastTime_StoresCorrectly()
    {
        var past = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeMilliseconds();
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = past
        };

        Assert.Equal(past, response.ExpiresAt);
    }

    [Fact]
    public void ExpiresAt_WithZero_StoresCorrectly()
    {
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = 0
        };

        Assert.Equal(0, response.ExpiresAt);
    }

    [Fact]
    public void ExpiresAt_WithMaxValue_StoresCorrectly()
    {
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = long.MaxValue
        };

        Assert.Equal(long.MaxValue, response.ExpiresAt);
    }

    [Fact]
    public void ExpiresAt_CanConvertToDateTime()
    {
        var timestamp = 1234567890000L;
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = timestamp
        };

        var dateTime = DateTimeOffset.FromUnixTimeMilliseconds(response.ExpiresAt);

        Assert.Equal(2009, dateTime.Year);
        Assert.Equal(2, dateTime.Month);
        Assert.Equal(13, dateTime.Day);
    }

    // ////////////////////////////////////
    //  ACCESS TOKEN TESTS
    // ////////////////////////////////////

    [Fact]
    public void AccessToken_WithJWTFormat_StoresCorrectly()
    {
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        var response = new TokenResponse
        {
            AccessToken = jwt,
            ExpiresAt = 1234567890000
        };

        Assert.Equal(jwt, response.AccessToken);
        Assert.Contains(".", response.AccessToken);
        Assert.Equal(3, response.AccessToken.Split('.').Length);
    }

    [Fact]
    public void AccessToken_WithOpaqueToken_StoresCorrectly()
    {
        var opaqueToken = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
        var response = new TokenResponse
        {
            AccessToken = opaqueToken,
            ExpiresAt = 1234567890000
        };

        Assert.Equal(opaqueToken, response.AccessToken);
    }

    [Fact]
    public void AccessToken_WithSpecialCharacters_StoresCorrectly()
    {
        var token = "token_with-special.chars+and/slashes=";
        var response = new TokenResponse
        {
            AccessToken = token,
            ExpiresAt = 1234567890000
        };

        Assert.Equal(token, response.AccessToken);
    }

    // ////////////////////////////////////
    //  EDGE CASES
    // ////////////////////////////////////

    [Fact]
    public void RoundTrip_SerializeAndDeserialize_PreservesData()
    {
        var original = new TokenResponse
        {
            AccessToken = "test_access_token",
            ExpiresAt = 1234567890000
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<TokenResponse>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.AccessToken, deserialized.AccessToken);
        Assert.Equal(original.ExpiresAt, deserialized.ExpiresAt);
    }

    [Fact]
    public void ExpiresAt_WithMillisecondPrecision_StoresExactValue()
    {
        var timestamp = 1234567890123L; // Includes milliseconds
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = timestamp
        };

        Assert.Equal(1234567890123L, response.ExpiresAt);
    }

    [Fact]
    public void AccessToken_WithVeryLongToken_SerializesCorrectly()
    {
        var longToken = new string('a', 2000);
        var response = new TokenResponse
        {
            AccessToken = longToken,
            ExpiresAt = 1234567890000
        };

        var json = JsonSerializer.Serialize(response);
        var deserialized = JsonSerializer.Deserialize<TokenResponse>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(longToken, deserialized.AccessToken);
    }

    [Fact]
    public void ExpiresAt_IsInMilliseconds_NotSeconds()
    {
        // Verify that the timestamp is in milliseconds, not seconds
        var oneHourFromNow = DateTimeOffset.UtcNow.AddHours(1);
        var milliseconds = oneHourFromNow.ToUnixTimeMilliseconds();
        var seconds = oneHourFromNow.ToUnixTimeSeconds();

        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = milliseconds
        };

        // Milliseconds should be much larger than seconds
        Assert.True(response.ExpiresAt > seconds);
        Assert.True(response.ExpiresAt.ToString().Length >= 13); // Milliseconds have at least 13 digits
    }

    [Fact]
    public void Compare_TwoResponses_WithSameData_AreNotSame()
    {
        var response1 = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = 1234567890000
        };

        var response2 = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = 1234567890000
        };

        // Different instances with same data
        Assert.NotSame(response1, response2);
        Assert.Equal(response1.AccessToken, response2.AccessToken);
        Assert.Equal(response1.ExpiresAt, response2.ExpiresAt);
    }

    [Fact]
    public void Serialize_WithUnicodeInAccessToken_HandlesCorrectly()
    {
        var token = "token_with_unicode_世界";
        var response = new TokenResponse
        {
            AccessToken = token,
            ExpiresAt = 1234567890000
        };

        var json = JsonSerializer.Serialize(response);
        var deserialized = JsonSerializer.Deserialize<TokenResponse>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(token, deserialized.AccessToken);
    }

    [Fact]
    public void ExpiresAt_WithNegativeValue_StoresCorrectly()
    {
        // While unusual, negative timestamps are technically valid (before Unix epoch)
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = -1000
        };

        Assert.Equal(-1000, response.ExpiresAt);
    }

    [Fact]
    public void JsonOutput_IsCompact_NoWhitespace()
    {
        var response = new TokenResponse
        {
            AccessToken = "test_token",
            ExpiresAt = 1234567890000
        };

        var json = JsonSerializer.Serialize(response);

        // Default serialization should be compact (no pretty-printing)
        Assert.DoesNotContain("  ", json);
        Assert.DoesNotContain("\n", json);
    }
}
