using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests;

public class UserInfoTests
{
    // ////////////////////////////////////
    //  CONSTRUCTOR/INITIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_WithRequiredPropertiesOnly_CreatesInstance()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband"
        };

        Assert.NotNull(userInfo);
        Assert.Equal("user123", userInfo.UserId);
        Assert.Equal("tenant123", userInfo.TenantId);
        Assert.Equal("app123", userInfo.ApplicationId);
        Assert.Equal("Wristband", userInfo.IdentityProviderName);
    }

    [Fact]
    public void Constructor_WithAllProperties_CreatesInstance()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            FullName = "John Doe",
            GivenName = "John",
            FamilyName = "Doe",
            MiddleName = "Michael",
            Nickname = "Johnny",
            DisplayName = "jdoe",
            PictureUrl = "https://example.com/photo.jpg",
            Gender = "male",
            Birthdate = "1990-01-01",
            TimeZone = "America/New_York",
            Locale = "en-US",
            UpdatedAt = 1234567890,
            Email = "john@example.com",
            EmailVerified = true,
            PhoneNumber = "+1234567890",
            PhoneNumberVerified = false,
            Roles = new List<UserInfoRole>
            {
                new UserInfoRole
                {
                    Id = "role1",
                    Name = "app:myapp:admin",
                    DisplayName = "Admin"
                }
            },
            CustomClaims = new Dictionary<string, object>
            {
                { "field1", "value1" },
                { "field2", 123L }
            }
        };

        Assert.NotNull(userInfo);
        Assert.Equal("John Doe", userInfo.FullName);
        Assert.Equal("john@example.com", userInfo.Email);
        Assert.NotNull(userInfo.Roles);
        Assert.Single(userInfo.Roles);
        Assert.NotNull(userInfo.CustomClaims);
        Assert.Equal(2, userInfo.CustomClaims.Count);
    }

    // ////////////////////////////////////
    //  EMPTY INSTANCE TESTS
    // ////////////////////////////////////

    [Fact]
    public void Empty_HasExpectedDefaultValues()
    {
        var empty = UserInfo.Empty;

        Assert.NotNull(empty);
        Assert.Equal(string.Empty, empty.UserId);
        Assert.Equal(string.Empty, empty.TenantId);
        Assert.Equal(string.Empty, empty.ApplicationId);
        Assert.Equal(string.Empty, empty.IdentityProviderName);

        // All optional fields should be null
        Assert.Null(empty.FullName);
        Assert.Null(empty.Email);
        Assert.Null(empty.EmailVerified);
        Assert.Null(empty.PhoneNumber);
        Assert.Null(empty.Roles);
        Assert.Null(empty.CustomClaims);
    }

    [Fact]
    public void Empty_IsSingletonInstance()
    {
        var empty1 = UserInfo.Empty;
        var empty2 = UserInfo.Empty;

        Assert.Same(empty1, empty2);
    }

    // ////////////////////////////////////
    //  JSON SERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Serialize_WithRequiredPropertiesOnly_ProducesCorrectJson()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband"
        };

        var json = JsonSerializer.Serialize(userInfo);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("user123", root.GetProperty("userId").GetString());
        Assert.Equal("tenant123", root.GetProperty("tenantId").GetString());
        Assert.Equal("app123", root.GetProperty("applicationId").GetString());
        Assert.Equal("Wristband", root.GetProperty("identityProviderName").GetString());
    }

    [Fact]
    public void Serialize_WithProfileScope_IncludesProfileFields()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            FullName = "John Doe",
            GivenName = "John",
            FamilyName = "Doe",
            DisplayName = "jdoe",
            TimeZone = "America/New_York"
        };

        var json = JsonSerializer.Serialize(userInfo);

        Assert.Contains("\"fullName\":", json);
        Assert.Contains("\"givenName\":", json);
        Assert.Contains("\"familyName\":", json);
        Assert.Contains("\"displayName\":", json);
        Assert.Contains("\"timeZone\":", json);
    }

    [Fact]
    public void Serialize_WithEmailScope_IncludesEmailFields()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            Email = "test@example.com",
            EmailVerified = true
        };

        var json = JsonSerializer.Serialize(userInfo);

        Assert.Contains("\"email\":", json);
        Assert.Contains("\"emailVerified\":", json);
    }

    [Fact]
    public void Serialize_WithPhoneScope_IncludesPhoneFields()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            PhoneNumber = "+1234567890",
            PhoneNumberVerified = false
        };

        var json = JsonSerializer.Serialize(userInfo);

        Assert.Contains("\"phoneNumber\":", json);
        Assert.Contains("\"phoneNumberVerified\":", json);
    }

    [Fact]
    public void Serialize_WithRoles_IncludesRolesArray()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            Roles = new List<UserInfoRole>
            {
                new UserInfoRole
                {
                    Id = "role1",
                    Name = "app:myapp:admin",
                    DisplayName = "Admin"
                }
            }
        };

        var json = JsonSerializer.Serialize(userInfo);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("roles", out var rolesElement));
        Assert.Equal(JsonValueKind.Array, rolesElement.ValueKind);
        Assert.Equal(1, rolesElement.GetArrayLength());
    }

    [Fact]
    public void Serialize_WithCustomClaims_IncludesCustomClaimsObject()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            CustomClaims = new Dictionary<string, object>
            {
                { "field1", "value1" },
                { "field2", 123L }
            }
        };

        var json = JsonSerializer.Serialize(userInfo);

        Assert.Contains("\"customClaims\":", json);
        Assert.Contains("\"field1\":", json);
        Assert.Contains("\"field2\":", json);
    }

    [Fact]
    public void Serialize_UsesCorrectJsonPropertyNames()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            FullName = "John Doe",
            DisplayName = "jdoe",
            PictureUrl = "https://example.com/photo.jpg",
            TimeZone = "America/New_York"
        };

        var json = JsonSerializer.Serialize(userInfo);

        // Should use camelCase from JsonPropertyName attributes
        Assert.Contains("\"userId\":", json);
        Assert.Contains("\"tenantId\":", json);
        Assert.Contains("\"applicationId\":", json);
        Assert.Contains("\"identityProviderName\":", json);
        Assert.Contains("\"fullName\":", json);
        Assert.Contains("\"displayName\":", json);
        Assert.Contains("\"pictureUrl\":", json);
        Assert.Contains("\"timeZone\":", json);

        // Should NOT use PascalCase C# property names
        Assert.DoesNotContain("\"UserId\":", json);
        Assert.DoesNotContain("\"FullName\":", json);
        Assert.DoesNotContain("\"DisplayName\":", json);
    }

    // ////////////////////////////////////
    //  JSON DESERIALIZATION TESTS
    // ////////////////////////////////////

    [Fact]
    public void Deserialize_WithRequiredFieldsOnly_CreatesInstance()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123"",
            ""applicationId"": ""app123"",
            ""identityProviderName"": ""Wristband""
        }";

        var userInfo = JsonSerializer.Deserialize<UserInfo>(json);

        Assert.NotNull(userInfo);
        Assert.Equal("user123", userInfo.UserId);
        Assert.Equal("tenant123", userInfo.TenantId);
        Assert.Equal("app123", userInfo.ApplicationId);
        Assert.Equal("Wristband", userInfo.IdentityProviderName);
    }

    [Fact]
    public void Deserialize_WithAllFields_CreatesInstance()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123"",
            ""applicationId"": ""app123"",
            ""identityProviderName"": ""Wristband"",
            ""fullName"": ""John Doe"",
            ""givenName"": ""John"",
            ""familyName"": ""Doe"",
            ""email"": ""test@example.com"",
            ""emailVerified"": true,
            ""phoneNumber"": ""+1234567890"",
            ""phoneNumberVerified"": false,
            ""roles"": [
                {
                    ""id"": ""role1"",
                    ""name"": ""app:myapp:admin"",
                    ""displayName"": ""Admin""
                }
            ],
            ""customClaims"": {
                ""field1"": ""value1""
            }
        }";

        var userInfo = JsonSerializer.Deserialize<UserInfo>(json);

        Assert.NotNull(userInfo);
        Assert.Equal("John Doe", userInfo.FullName);
        Assert.Equal("test@example.com", userInfo.Email);
        Assert.True(userInfo.EmailVerified);
        Assert.NotNull(userInfo.Roles);
        Assert.Single(userInfo.Roles);
        Assert.NotNull(userInfo.CustomClaims);
    }

    [Fact]
    public void Deserialize_WithMissingRequiredField_ThrowsJsonException()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123"",
            ""applicationId"": ""app123""
        }";

        var exception = Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<UserInfo>(json));

        Assert.Contains("identityProviderName", exception.Message);
    }

    [Fact]
    public void Deserialize_WithNullOptionalFields_LeavesFieldsNull()
    {
        var json = @"{
            ""userId"": ""user123"",
            ""tenantId"": ""tenant123"",
            ""applicationId"": ""app123"",
            ""identityProviderName"": ""Wristband"",
            ""email"": null,
            ""roles"": null,
            ""customClaims"": null
        }";

        var userInfo = JsonSerializer.Deserialize<UserInfo>(json);

        Assert.NotNull(userInfo);
        Assert.Null(userInfo.Email);
        Assert.Null(userInfo.Roles);
        Assert.Null(userInfo.CustomClaims);
    }

    // ////////////////////////////////////
    //  PROPERTY BEHAVIOR TESTS
    // ////////////////////////////////////

    [Fact]
    public void Properties_AreInitOnly_CannotBeModifiedAfterConstruction()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband"
        };

        // This should not compile - init-only properties
        // userInfo.UserId = "different";
        // userInfo.Email = "different@example.com";

        Assert.Equal("user123", userInfo.UserId);
    }

    [Fact]
    public void UpdatedAt_WithValidUnixTimestamp_StoresCorrectly()
    {
        var timestamp = 1234567890L;
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            UpdatedAt = timestamp
        };

        Assert.Equal(timestamp, userInfo.UpdatedAt);
    }

    [Fact]
    public void EmailVerified_WithTrueValue_StoresCorrectly()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            EmailVerified = true
        };

        Assert.NotNull(userInfo.EmailVerified);
        Assert.True(userInfo.EmailVerified);
    }

    [Fact]
    public void EmailVerified_WithFalseValue_StoresCorrectly()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            EmailVerified = false
        };

        Assert.NotNull(userInfo.EmailVerified);
        Assert.False(userInfo.EmailVerified);
    }

    [Fact]
    public void Roles_CanContainMultipleRoles()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            Roles = new List<UserInfoRole>
            {
                new UserInfoRole { Id = "role1", Name = "app:myapp:admin", DisplayName = "Admin" },
                new UserInfoRole { Id = "role2", Name = "app:myapp:user", DisplayName = "User" }
            }
        };

        Assert.NotNull(userInfo.Roles);
        Assert.Equal(2, userInfo.Roles.Count);
    }

    [Fact]
    public void CustomClaims_CanContainVariousTypes()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            CustomClaims = new Dictionary<string, object>
            {
                { "stringField", "value" },
                { "numberField", 123L },
                { "boolField", true }
            }
        };

        Assert.NotNull(userInfo.CustomClaims);
        Assert.Equal(3, userInfo.CustomClaims.Count);
        Assert.Equal("value", userInfo.CustomClaims["stringField"]);
        Assert.Equal(123L, userInfo.CustomClaims["numberField"]);
        Assert.Equal(true, userInfo.CustomClaims["boolField"]);
    }

    // ////////////////////////////////////
    //  EDGE CASES
    // ////////////////////////////////////

    [Fact]
    public void Birthdate_WithValidISO8601Format_StoresCorrectly()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            Birthdate = "1990-01-01"
        };

        Assert.Equal("1990-01-01", userInfo.Birthdate);
    }

    [Fact]
    public void PhoneNumber_WithE164Format_StoresCorrectly()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            PhoneNumber = "+12025551234"
        };

        Assert.Equal("+12025551234", userInfo.PhoneNumber);
    }

    [Fact]
    public void Locale_WithBCP47Format_StoresCorrectly()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            Locale = "en-US"
        };

        Assert.Equal("en-US", userInfo.Locale);
    }

    [Fact]
    public void RoundTrip_SerializeAndDeserialize_PreservesData()
    {
        var original = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            FullName = "John Doe",
            Email = "test@example.com",
            EmailVerified = true,
            UpdatedAt = 1234567890,
            Roles = new List<UserInfoRole>
            {
                new UserInfoRole { Id = "role1", Name = "app:myapp:admin", DisplayName = "Admin" }
            }
        };

        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<UserInfo>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(original.UserId, deserialized.UserId);
        Assert.Equal(original.TenantId, deserialized.TenantId);
        Assert.Equal(original.ApplicationId, deserialized.ApplicationId);
        Assert.Equal(original.IdentityProviderName, deserialized.IdentityProviderName);
        Assert.Equal(original.FullName, deserialized.FullName);
        Assert.Equal(original.Email, deserialized.Email);
        Assert.Equal(original.EmailVerified, deserialized.EmailVerified);
        Assert.Equal(original.UpdatedAt, deserialized.UpdatedAt);
        Assert.NotNull(deserialized.Roles);
        Assert.Single(deserialized.Roles);
    }

    [Fact]
    public void FullName_WithUnicodeCharacters_StoresCorrectly()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            FullName = "José García 李明"
        };

        Assert.Equal("José García 李明", userInfo.FullName);
    }

    [Fact]
    public void Gender_WithCustomValue_StoresCorrectly()
    {
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant123",
            ApplicationId = "app123",
            IdentityProviderName = "Wristband",
            Gender = "non-binary"
        };

        Assert.Equal("non-binary", userInfo.Gender);
    }
}
