using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests;

public class UserInfoRoleTests
{
    // ////////////////////////////////////
    //  CONSTRUCTOR/INITIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_WithAllRequiredProperties_CreatesInstance()
    {
        var role = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Administrator"
        };

        Assert.NotNull(role);
        Assert.Equal("role123", role.Id);
        Assert.Equal("app:myapp:admin", role.Name);
        Assert.Equal("Administrator", role.DisplayName);
    }

    [Fact]
    public void Constructor_WithMinimalData_CreatesInstance()
    {
        var role = new UserInfoRole
        {
            Id = "1",
            Name = "a",
            DisplayName = "A"
        };

        Assert.NotNull(role);
        Assert.Equal("1", role.Id);
        Assert.Equal("a", role.Name);
        Assert.Equal("A", role.DisplayName);
    }

    // ////////////////////////////////////
    //  JSON SERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Serialize_WithAllProperties_ProducesCorrectJson()
    {
        var role = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Administrator"
        };

        var json = JsonSerializer.Serialize(role);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("role123", root.GetProperty("id").GetString());
        Assert.Equal("app:myapp:admin", root.GetProperty("name").GetString());
        Assert.Equal("Administrator", root.GetProperty("displayName").GetString());
    }

    [Fact]
    public void Serialize_UsesCorrectJsonPropertyNames()
    {
        var role = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Administrator"
        };

        var json = JsonSerializer.Serialize(role);

        // Should use camelCase property names from JsonPropertyName attributes
        Assert.Contains("\"id\":", json);
        Assert.Contains("\"name\":", json);
        Assert.Contains("\"displayName\":", json);

        // Should NOT use PascalCase C# property names
        Assert.DoesNotContain("\"Id\":", json);
        Assert.DoesNotContain("\"Name\":", json);
        Assert.DoesNotContain("\"DisplayName\":", json);
    }

    // ////////////////////////////////////
    //  JSON DESERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Deserialize_WithValidJson_CreatesInstance()
    {
        var json = @"{
            ""id"": ""role123"",
            ""name"": ""app:myapp:admin"",
            ""displayName"": ""Administrator""
        }";

        var role = JsonSerializer.Deserialize<UserInfoRole>(json);

        Assert.NotNull(role);
        Assert.Equal("role123", role.Id);
        Assert.Equal("app:myapp:admin", role.Name);
        Assert.Equal("Administrator", role.DisplayName);
    }

    [Fact]
    public void Deserialize_WithSnakeCaseDisplayName_ThrowsJsonException()
    {
        // Tests that we only support camelCase, not snake_case
        var json = @"{
            ""id"": ""role123"",
            ""name"": ""app:myapp:admin"",
            ""display_name"": ""Administrator""
        }";

        // Required property displayName is missing (display_name doesn't match)
        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<UserInfoRole>(json));

        Assert.Contains("displayName", exception.Message);
    }

    [Fact]
    public void Deserialize_WithCamelCaseDisplayName_Succeeds()
    {
        var json = @"{
            ""id"": ""role123"",
            ""name"": ""app:myapp:admin"",
            ""displayName"": ""Administrator""
        }";

        var role = JsonSerializer.Deserialize<UserInfoRole>(json);

        Assert.NotNull(role);
        Assert.Equal("Administrator", role.DisplayName);
    }

    [Fact]
    public void Deserialize_WithMissingRequiredField_ThrowsJsonException()
    {
        var json = @"{
            ""id"": ""role123"",
            ""name"": ""app:myapp:admin""
        }";

        // Required property displayName is missing
        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<UserInfoRole>(json));

        Assert.Contains("displayName", exception.Message);
        Assert.Contains("required", exception.Message.ToLower());
    }

    // ////////////////////////////////////
    //  PROPERTY BEHAVIOR TESTS
    // ////////////////////////////////////

    [Fact]
    public void Properties_AreInitOnly_CannotBeModified()
    {
        var role = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Administrator"
        };

        // This should not compile - init-only properties
        // role.Id = "different";
        // role.Name = "different";
        // role.DisplayName = "different";

        // Verify properties are set
        Assert.Equal("role123", role.Id);
        Assert.Equal("app:myapp:admin", role.Name);
        Assert.Equal("Administrator", role.DisplayName);
    }

    [Fact]
    public void RoleName_WithColonSeparatedFormat_IsValid()
    {
        var role = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Administrator"
        };

        Assert.Contains(":", role.Name);
        var parts = role.Name.Split(':');
        Assert.Equal(3, parts.Length);
        Assert.Equal("app", parts[0]);
        Assert.Equal("myapp", parts[1]);
        Assert.Equal("admin", parts[2]);
    }

    [Fact]
    public void RoleName_WithDifferentFormats_IsAccepted()
    {
        // Role names can have various formats
        var formats = new[]
        {
            "app:myapp:admin",
            "tenant:t1:user",
            "org:acme:owner",
            "simple_role",
            "UPPERCASE",
            "kebab-case-role"
        };

        foreach (var format in formats)
        {
            var role = new UserInfoRole
            {
                Id = "id",
                Name = format,
                DisplayName = "Test"
            };

            Assert.Equal(format, role.Name);
        }
    }

    // ////////////////////////////////////
    //  EDGE CASES
    // ////////////////////////////////////

    [Fact]
    public void Id_WithSpecialCharacters_IsAccepted()
    {
        var role = new UserInfoRole
        {
            Id = "role-123_abc.def",
            Name = "app:myapp:admin",
            DisplayName = "Administrator"
        };

        Assert.Equal("role-123_abc.def", role.Id);
    }

    [Fact]
    public void DisplayName_WithUnicodeCharacters_IsAccepted()
    {
        var role = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Administratör 管理员"
        };

        Assert.Equal("Administratör 管理员", role.DisplayName);
    }

    [Fact]
    public void DisplayName_WithWhitespace_IsAccepted()
    {
        var role = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Super Administrator Role"
        };

        Assert.Equal("Super Administrator Role", role.DisplayName);
    }

    [Fact]
    public void RoundTrip_SerializeAndDeserialize_PreservesData()
    {
        var original = new UserInfoRole
        {
            Id = "role123",
            Name = "app:myapp:admin",
            DisplayName = "Administrator"
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<UserInfoRole>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.Id, deserialized.Id);
        Assert.Equal(original.Name, deserialized.Name);
        Assert.Equal(original.DisplayName, deserialized.DisplayName);
    }
}
