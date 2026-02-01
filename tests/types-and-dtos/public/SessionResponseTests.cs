using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests;

public class SessionResponseTests
{
    // ////////////////////////////////////
    //  CONSTRUCTOR/INITIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_WithRequiredPropertiesOnly_CreatesInstance()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123"
        };

        Assert.NotNull(response);
        Assert.Equal("user123", response.UserId);
        Assert.Equal("tenant123", response.TenantId);
        Assert.Null(response.Metadata);
    }

    [Fact]
    public void Constructor_WithAllProperties_CreatesInstance()
    {
        var metadata = new { key = "value", count = 42 };
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        Assert.NotNull(response);
        Assert.Equal("user123", response.UserId);
        Assert.Equal("tenant123", response.TenantId);
        Assert.NotNull(response.Metadata);
    }

    [Fact]
    public void Constructor_WithMinimalData_CreatesInstance()
    {
        var response = new SessionResponse
        {
            UserId = "a",
            TenantId = "b"
        };

        Assert.Equal("a", response.UserId);
        Assert.Equal("b", response.TenantId);
    }

    // ////////////////////////////////////
    //  JSON SERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Serialize_WithRequiredPropertiesOnly_ProducesCorrectJson()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123"
        };

        var json = JsonSerializer.Serialize(response);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("user123", root.GetProperty("userId").GetString());
        Assert.Equal("tenant123", root.GetProperty("tenantId").GetString());

        // Metadata should be included as null
        Assert.True(root.TryGetProperty("metadata", out var metadataElement));
        Assert.Equal(JsonValueKind.Null, metadataElement.ValueKind);
    }

    [Fact]
    public void Serialize_WithMetadata_IncludesMetadataObject()
    {
        var metadata = new Dictionary<string, object>
        {
            { "key1", "value1" },
            { "key2", 123 }
        };

        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        var json = JsonSerializer.Serialize(response);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("metadata", out var metadataElement));
        Assert.Equal(JsonValueKind.Object, metadataElement.ValueKind);
    }

    [Fact]
    public void Serialize_UsesCorrectJsonPropertyNames()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123"
        };

        var json = JsonSerializer.Serialize(response);

        // Should use camelCase from JsonPropertyName attributes
        Assert.Contains("\"userId\":", json);
        Assert.Contains("\"tenantId\":", json);
        Assert.Contains("\"metadata\":", json);

        // Should NOT use PascalCase C# property names
        Assert.DoesNotContain("\"UserId\":", json);
        Assert.DoesNotContain("\"TenantId\":", json);
        Assert.DoesNotContain("\"Metadata\":", json);
    }

    [Fact]
    public void Serialize_MatchesWristbandFrontendSDKFormat()
    {
        // This format must match what Wristband frontend SDKs expect
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = new { customField = "value" }
        };

        var json = JsonSerializer.Serialize(response);

        // Verify expected structure
        Assert.Contains("\"userId\":\"user123\"", json);
        Assert.Contains("\"tenantId\":\"tenant123\"", json);
        Assert.Contains("\"metadata\":", json);
    }

    // ////////////////////////////////////
    //  JSON DESERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Deserialize_WithRequiredFieldsOnly_CreatesInstance()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123""
        }";

        var response = JsonSerializer.Deserialize<SessionResponse>(json);

        Assert.NotNull(response);
        Assert.Equal("user123", response.UserId);
        Assert.Equal("tenant123", response.TenantId);
        Assert.Null(response.Metadata);
    }

    [Fact]
    public void Deserialize_WithAllFields_CreatesInstance()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123"",
            ""metadata"": {
                ""key1"": ""value1"",
                ""key2"": 123
            }
        }";

        var response = JsonSerializer.Deserialize<SessionResponse>(json);

        Assert.NotNull(response);
        Assert.Equal("user123", response.UserId);
        Assert.Equal("tenant123", response.TenantId);
        Assert.NotNull(response.Metadata);
    }

    [Fact]
    public void Deserialize_WithNullMetadata_LeavesMetadataNull()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123"",
            ""metadata"": null
        }";

        var response = JsonSerializer.Deserialize<SessionResponse>(json);

        Assert.NotNull(response);
        Assert.Null(response.Metadata);
    }

    [Fact]
    public void Deserialize_WithMissingUserId_ThrowsJsonException()
    {
        var json = @"{
            ""tenantId"": ""tenant123""
        }";

        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<SessionResponse>(json));

        Assert.Contains("userId", exception.Message);
    }

    [Fact]
    public void Deserialize_WithMissingTenantId_ThrowsJsonException()
    {
        var json = @"{
            ""userId"": ""user123""
        }";

        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<SessionResponse>(json));

        Assert.Contains("tenantId", exception.Message);
    }

    [Fact]
    public void Deserialize_WithMissingMetadata_LeavesMetadataNull()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123""
        }";

        var response = JsonSerializer.Deserialize<SessionResponse>(json);

        Assert.NotNull(response);
        Assert.Null(response.Metadata);
    }

    // ////////////////////////////////////
    //  METADATA TESTS
    // ////////////////////////////////////

    [Fact]
    public void Metadata_CanBeStringValue()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = "simple string"
        };

        Assert.Equal("simple string", response.Metadata);
    }

    [Fact]
    public void Metadata_CanBeNumericValue()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = 42
        };

        Assert.Equal(42, response.Metadata);
    }

    [Fact]
    public void Metadata_CanBeBooleanValue()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = true
        };

        Assert.Equal(true, response.Metadata);
    }

    [Fact]
    public void Metadata_CanBeAnonymousObject()
    {
        var metadata = new { name = "test", value = 123, active = true };
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        Assert.NotNull(response.Metadata);
    }

    [Fact]
    public void Metadata_CanBeDictionary()
    {
        var metadata = new Dictionary<string, object>
        {
            { "key1", "value1" },
            { "key2", 123 },
            { "key3", true }
        };

        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        Assert.NotNull(response.Metadata);
        var dict = Assert.IsType<Dictionary<string, object>>(response.Metadata);
        Assert.Equal(3, dict.Count);
    }

    [Fact]
    public void Metadata_CanBeArray()
    {
        var metadata = new[] { "item1", "item2", "item3" };
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        Assert.NotNull(response.Metadata);
    }

    [Fact]
    public void Metadata_CanBeNestedObject()
    {
        var metadata = new
        {
            user = new { name = "John", age = 30 },
            settings = new { theme = "dark", notifications = true }
        };

        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        Assert.NotNull(response.Metadata);
    }

    [Fact]
    public void Metadata_SerializesComplexObjectCorrectly()
    {
        var metadata = new Dictionary<string, object>
        {
            { "user", new { name = "John", roles = new[] { "admin", "user" } } },
            { "settings", new { theme = "dark" } }
        };

        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        var json = JsonSerializer.Serialize(response);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("metadata", out var metadataElement));
        Assert.Equal(JsonValueKind.Object, metadataElement.ValueKind);
    }

    // ////////////////////////////////////
    //  PROPERTY BEHAVIOR TESTS
    // ////////////////////////////////////

    [Fact]
    public void Properties_AreInitOnly_CannotBeModifiedAfterConstruction()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123"
        };

        // This should not compile - init-only properties
        // response.UserId = "different";
        // response.TenantId = "different";
        // response.Metadata = new { };

        Assert.Equal("user123", response.UserId);
        Assert.Equal("tenant123", response.TenantId);
    }

    // ////////////////////////////////////
    //  EDGE CASES
    // ////////////////////////////////////

    [Fact]
    public void UserId_WithSpecialCharacters_StoresCorrectly()
    {
        var response = new SessionResponse
        {
            UserId = "user-123_abc.def",
            TenantId = "tenant123"
        };

        Assert.Equal("user-123_abc.def", response.UserId);
    }

    [Fact]
    public void TenantId_WithSpecialCharacters_StoresCorrectly()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant-456_xyz.ghi"
        };

        Assert.Equal("tenant-456_xyz.ghi", response.TenantId);
    }

    [Fact]
    public void Metadata_WithUnicodeCharacters_StoresCorrectly()
    {
        var metadata = new { message = "Hello 世界 🌍" };
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = metadata
        };

        Assert.NotNull(response.Metadata);
    }

    [Fact]
    public void RoundTrip_SerializeAndDeserialize_PreservesData()
    {
        var original = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = new Dictionary<string, object>
            {
                { "key1", "value1" },
                { "key2", 123 }
            }
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<SessionResponse>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.UserId, deserialized.UserId);
        Assert.Equal(original.TenantId, deserialized.TenantId);
        Assert.NotNull(deserialized.Metadata);
    }

    [Fact]
    public void RoundTrip_WithNullMetadata_PreservesNull()
    {
        var original = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = null
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<SessionResponse>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.UserId, deserialized.UserId);
        Assert.Equal(original.TenantId, deserialized.TenantId);
        Assert.Null(deserialized.Metadata);
    }

    [Fact]
    public void Metadata_WithEmptyObject_SerializesCorrectly()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = new { }
        };

        var json = JsonSerializer.Serialize(response);

        Assert.Contains("\"metadata\":{}", json);
    }

    [Fact]
    public void Metadata_WithEmptyDictionary_SerializesCorrectly()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = new Dictionary<string, object>()
        };

        var json = JsonSerializer.Serialize(response);

        Assert.Contains("\"metadata\":{}", json);
    }

    [Fact]
    public void Metadata_WithEmptyArray_SerializesCorrectly()
    {
        var response = new SessionResponse
        {
            UserId = "user123",
            TenantId = "tenant123",
            Metadata = new object[] { }
        };

        var json = JsonSerializer.Serialize(response);

        Assert.Contains("\"metadata\":[]", json);
    }
}
