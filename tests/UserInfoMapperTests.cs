using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests;

public class UserInfoMapperTests
{
    // ////////////////////////////////////
    //  SUCCESSFUL MAPPING TESTS
    // ////////////////////////////////////

    [Fact]
    public void MapUserInfo_WithAllRequiredClaims_ReturnsUserInfo()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result);
        Assert.Equal("user123", result.UserId);
        Assert.Equal("tenant123", result.TenantId);
        Assert.Equal("app123", result.ApplicationId);
        Assert.Equal("Wristband", result.IdentityProviderName);
    }

    [Fact]
    public void MapUserInfo_WithProfileScope_MapsAllProfileFields()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""name"": ""John Doe"",
            ""given_name"": ""John"",
            ""family_name"": ""Doe"",
            ""middle_name"": ""Michael"",
            ""nickname"": ""Johnny"",
            ""preferred_username"": ""jdoe"",
            ""picture"": ""https://example.com/photo.jpg"",
            ""gender"": ""male"",
            ""birthdate"": ""1990-01-01"",
            ""zoneinfo"": ""America/New_York"",
            ""locale"": ""en-US"",
            ""updated_at"": 1234567890
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Equal("John Doe", result.FullName);
        Assert.Equal("John", result.GivenName);
        Assert.Equal("Doe", result.FamilyName);
        Assert.Equal("Michael", result.MiddleName);
        Assert.Equal("Johnny", result.Nickname);
        Assert.Equal("jdoe", result.DisplayName);
        Assert.Equal("https://example.com/photo.jpg", result.PictureUrl);
        Assert.Equal("male", result.Gender);
        Assert.Equal("1990-01-01", result.Birthdate);
        Assert.Equal("America/New_York", result.TimeZone);
        Assert.Equal("en-US", result.Locale);
        Assert.Equal(1234567890, result.UpdatedAt);
    }

    [Fact]
    public void MapUserInfo_WithEmailScope_MapsEmailFields()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""email"": ""test@example.com"",
            ""email_verified"": true
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Equal("test@example.com", result.Email);
        Assert.True(result.EmailVerified);
    }

    [Fact]
    public void MapUserInfo_WithPhoneScope_MapsPhoneFields()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""phone_number"": ""+1234567890"",
            ""phone_number_verified"": false
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Equal("+1234567890", result.PhoneNumber);
        Assert.False(result.PhoneNumberVerified);
    }

    [Fact]
    public void MapUserInfo_WithRolesScope_MapsRoles()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""roles"": [
                {
                    ""id"": ""role1"",
                    ""name"": ""app:myapp:admin"",
                    ""display_name"": ""Admin""
                },
                {
                    ""id"": ""role2"",
                    ""name"": ""app:myapp:user"",
                    ""display_name"": ""User""
                }
            ]
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.Roles);
        Assert.Equal(2, result.Roles.Count);
        Assert.Equal("role1", result.Roles[0].Id);
        Assert.Equal("app:myapp:admin", result.Roles[0].Name);
        Assert.Equal("Admin", result.Roles[0].DisplayName);
        Assert.Equal("role2", result.Roles[1].Id);
        Assert.Equal("app:myapp:user", result.Roles[1].Name);
        Assert.Equal("User", result.Roles[1].DisplayName);
    }

    [Fact]
    public void MapUserInfo_WithRolesCamelCase_MapsRoles()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""roles"": [
                {
                    ""id"": ""role1"",
                    ""name"": ""app:myapp:admin"",
                    ""displayName"": ""Admin""
                }
            ]
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.Roles);
        Assert.Single(result.Roles);
        Assert.Equal("Admin", result.Roles[0].DisplayName);
    }

    [Fact]
    public void MapUserInfo_WithCustomClaims_MapsCustomClaims()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""custom_claims"": {
                ""fieldA"": ""valueA"",
                ""fieldB"": 123,
                ""fieldC"": true
            }
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.CustomClaims);
        Assert.Equal(3, result.CustomClaims.Count);
        Assert.Equal("valueA", result.CustomClaims["fieldA"]);
        Assert.Equal(123L, result.CustomClaims["fieldB"]);
        Assert.Equal(true, result.CustomClaims["fieldC"]);
    }

    [Fact]
    public void MapUserInfo_WithNestedCustomClaims_MapsNestedObjects()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""custom_claims"": {
                ""nested"": {
                    ""key1"": ""value1"",
                    ""key2"": ""value2""
                },
                ""array"": [1, 2, 3]
            }
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.CustomClaims);
        Assert.True(result.CustomClaims.ContainsKey("nested"));
        Assert.True(result.CustomClaims.ContainsKey("array"));
    }

    // ////////////////////////////////////
    //  NULL/MISSING OPTIONAL FIELDS TESTS
    // ////////////////////////////////////

    [Fact]
    public void MapUserInfo_WithMissingOptionalFields_ReturnsNulls()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Null(result.FullName);
        Assert.Null(result.Email);
        Assert.Null(result.EmailVerified);
        Assert.Null(result.PhoneNumber);
        Assert.Null(result.PhoneNumberVerified);
        Assert.Null(result.Roles);
        Assert.Null(result.CustomClaims);
    }

    [Fact]
    public void MapUserInfo_WithNullOptionalFields_ReturnsNulls()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""email"": null,
            ""phone_number"": null,
            ""roles"": null,
            ""custom_claims"": null
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Null(result.Email);
        Assert.Null(result.PhoneNumber);
        Assert.Null(result.Roles);
        Assert.Null(result.CustomClaims);
    }

    [Fact]
    public void MapUserInfo_WithEmptyRolesArray_ReturnsNull()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""roles"": []
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Null(result.Roles);
    }

    [Fact]
    public void MapUserInfo_WithInvalidRoleObjects_SkipsThem()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""roles"": [
                {
                    ""id"": ""role1"",
                    ""name"": ""app:myapp:admin"",
                    ""display_name"": ""Admin""
                },
                {
                    ""id"": ""role2"",
                    ""name"": ""app:myapp:user""
                },
                {
                    ""id"": """",
                    ""name"": ""app:myapp:guest"",
                    ""display_name"": ""Guest""
                }
            ]
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.Roles);
        Assert.Single(result.Roles);
        Assert.Equal("role1", result.Roles[0].Id);
    }

    [Fact]
    public void MapUserInfo_WithNonObjectRoleElements_SkipsThem()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""roles"": [
                ""invalid_role"",
                {
                    ""id"": ""role1"",
                    ""name"": ""app:myapp:admin"",
                    ""display_name"": ""Admin""
                }
            ]
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.Roles);
        Assert.Single(result.Roles);
        Assert.Equal("role1", result.Roles[0].Id);
    }

    [Fact]
    public void MapUserInfo_WithNonArrayRoles_ReturnsNull()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""roles"": ""not-an-array""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Null(result.Roles);
    }

    [Fact]
    public void MapUserInfo_WithNonObjectCustomClaims_ReturnsNull()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""custom_claims"": ""not-an-object""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Null(result.CustomClaims);
    }

    // ////////////////////////////////////
    //  ERROR HANDLING TESTS
    // ////////////////////////////////////

    [Fact]
    public void MapUserInfo_WithNullRawUserInfo_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() =>
            UserInfoMapper.MapUserInfo(null!));

        Assert.Equal("rawUserInfo", exception.ParamName);
    }

    [Fact]
    public void MapUserInfo_WithMissingSub_ThrowsInvalidOperationException()
    {
        var json = @"{
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            UserInfoMapper.MapUserInfo(rawUserInfo));

        Assert.Contains("sub", exception.Message);
        Assert.Contains("missing", exception.Message);
    }

    [Fact]
    public void MapUserInfo_WithMissingTenantId_ThrowsInvalidOperationException()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            UserInfoMapper.MapUserInfo(rawUserInfo));

        Assert.Contains("tnt_id", exception.Message);
        Assert.Contains("missing", exception.Message);
    }

    [Fact]
    public void MapUserInfo_WithMissingAppId_ThrowsInvalidOperationException()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""idp_name"": ""Wristband""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            UserInfoMapper.MapUserInfo(rawUserInfo));

        Assert.Contains("app_id", exception.Message);
        Assert.Contains("missing", exception.Message);
    }

    [Fact]
    public void MapUserInfo_WithMissingIdpName_ThrowsInvalidOperationException()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            UserInfoMapper.MapUserInfo(rawUserInfo));

        Assert.Contains("idp_name", exception.Message);
        Assert.Contains("missing", exception.Message);
    }

    [Fact]
    public void MapUserInfo_WithEmptySub_ThrowsInvalidOperationException()
    {
        var json = @"{
            ""sub"": """",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            UserInfoMapper.MapUserInfo(rawUserInfo));

        Assert.Contains("sub", exception.Message);
        Assert.Contains("cannot be null or empty", exception.Message);
    }

    [Fact]
    public void MapUserInfo_WithNullSub_ThrowsInvalidOperationException()
    {
        var json = @"{
            ""sub"": null,
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband""
        }";
        var rawUserInfo = new RawUserInfo(json);

        var exception = Assert.Throws<InvalidOperationException>(() =>
            UserInfoMapper.MapUserInfo(rawUserInfo));

        Assert.Contains("sub", exception.Message);
    }

    // ////////////////////////////////////
    //  EDGE CASES
    // ////////////////////////////////////

    [Fact]
    public void MapUserInfo_WithComplexNestedCustomClaims_MapsCorrectly()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""custom_claims"": {
                ""string"": ""text"",
                ""number"": 42,
                ""boolean"": true,
                ""null_value"": null,
                ""nested_object"": {
                    ""inner_key"": ""inner_value""
                },
                ""array"": [1, 2, 3],
                ""mixed_array"": [""string"", 123, true, null]
            }
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.CustomClaims);
        Assert.Equal("text", result.CustomClaims["string"]);
        Assert.Equal(42L, result.CustomClaims["number"]);
        Assert.Equal(true, result.CustomClaims["boolean"]);
        Assert.Null(result.CustomClaims["null_value"]);

        var nestedObj = result.CustomClaims["nested_object"] as Dictionary<string, object>;
        Assert.NotNull(nestedObj);

        var array = result.CustomClaims["array"] as List<object>;
        Assert.NotNull(array);
        Assert.Equal(3, array.Count);
    }

    [Fact]
    public void MapUserInfo_WithEmailVerifiedFalse_ReturnsFalse()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""email_verified"": false
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.EmailVerified);
        Assert.False(result.EmailVerified);
    }

    [Fact]
    public void MapUserInfo_WithUpdatedAtZero_ReturnsZero()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""updated_at"": 0
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.NotNull(result.UpdatedAt);
        Assert.Equal(0, result.UpdatedAt);
    }

    [Fact]
    public void MapUserInfo_WithLargeUpdatedAt_ReturnsCorrectValue()
    {
        var json = @"{
            ""sub"": ""user123"",
            ""tnt_id"": ""tenant123"",
            ""app_id"": ""app123"",
            ""idp_name"": ""Wristband"",
            ""updated_at"": 9999999999
        }";
        var rawUserInfo = new RawUserInfo(json);

        var result = UserInfoMapper.MapUserInfo(rawUserInfo);

        Assert.Equal(9999999999, result.UpdatedAt);
    }
}
