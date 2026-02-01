using System.Text.Json;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Maps raw OIDC userinfo claims to the structured UserInfo model with friendly field names.
/// </summary>
internal static class UserInfoMapper
{
    /// <summary>
    /// Transforms raw userinfo claims from Wristband's OIDC endpoint to the structured UserInfo type.
    /// Maps snake_case OIDC claims to camelCase properties matching Wristband's User entity field names.
    /// </summary>
    /// <param name="rawUserInfo">The raw userinfo claims from Wristband.</param>
    /// <returns>Structured UserInfo object with friendly property names.</returns>
    /// <exception cref="ArgumentNullException">Thrown when rawUserInfo is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when required claims are missing.</exception>
    public static UserInfo MapUserInfo(RawUserInfo rawUserInfo)
    {
        if (rawUserInfo == null)
        {
            throw new ArgumentNullException(nameof(rawUserInfo));
        }

        // Extract required claims (always present)
        var userId = GetRequiredString(rawUserInfo, "sub");
        var tenantId = GetRequiredString(rawUserInfo, "tnt_id");
        var applicationId = GetRequiredString(rawUserInfo, "app_id");
        var identityProviderName = GetRequiredString(rawUserInfo, "idp_name");

        return new UserInfo
        {
            // Always returned - mapped from OIDC standard claims
            UserId = userId,
            TenantId = tenantId,
            ApplicationId = applicationId,
            IdentityProviderName = identityProviderName,

            // Profile scope - mapped to User entity field names
            FullName = GetOptionalString(rawUserInfo, "name"),
            GivenName = GetOptionalString(rawUserInfo, "given_name"),
            FamilyName = GetOptionalString(rawUserInfo, "family_name"),
            MiddleName = GetOptionalString(rawUserInfo, "middle_name"),
            Nickname = GetOptionalString(rawUserInfo, "nickname"),
            DisplayName = GetOptionalString(rawUserInfo, "preferred_username"),
            PictureUrl = GetOptionalString(rawUserInfo, "picture"),
            Gender = GetOptionalString(rawUserInfo, "gender"),
            Birthdate = GetOptionalString(rawUserInfo, "birthdate"),
            TimeZone = GetOptionalString(rawUserInfo, "zoneinfo"),
            Locale = GetOptionalString(rawUserInfo, "locale"),
            UpdatedAt = GetOptionalLong(rawUserInfo, "updated_at"),

            // Email scope
            Email = GetOptionalString(rawUserInfo, "email"),
            EmailVerified = GetOptionalBool(rawUserInfo, "email_verified"),

            // Phone scope
            PhoneNumber = GetOptionalString(rawUserInfo, "phone_number"),
            PhoneNumberVerified = GetOptionalBool(rawUserInfo, "phone_number_verified"),

            // Roles scope
            Roles = MapRoles(rawUserInfo),

            // Custom claims
            CustomClaims = GetOptionalDictionary(rawUserInfo, "custom_claims"),
        };
    }

    /// <summary>
    /// Gets a required string claim value.
    /// </summary>
    private static string GetRequiredString(RawUserInfo rawUserInfo, string claimName)
    {
        if (!rawUserInfo.TryGetValue(claimName, out var element))
        {
            throw new InvalidOperationException($"Required claim '{claimName}' is missing from userinfo.");
        }

        var value = element.GetString();
        if (string.IsNullOrEmpty(value))
        {
            throw new InvalidOperationException($"Required claim '{claimName}' cannot be null or empty.");
        }

        return value;
    }

    /// <summary>
    /// Gets an optional string claim value.
    /// </summary>
    private static string? GetOptionalString(RawUserInfo rawUserInfo, string claimName)
    {
        if (!rawUserInfo.TryGetValue(claimName, out var element))
        {
            return null;
        }

        return element.ValueKind == JsonValueKind.Null ? null : element.GetString();
    }

    /// <summary>
    /// Gets an optional boolean claim value.
    /// </summary>
    private static bool? GetOptionalBool(RawUserInfo rawUserInfo, string claimName)
    {
        if (!rawUserInfo.TryGetValue(claimName, out var element))
        {
            return null;
        }

        return element.ValueKind == JsonValueKind.Null ? null : element.GetBoolean();
    }

    /// <summary>
    /// Gets an optional long claim value.
    /// </summary>
    private static long? GetOptionalLong(RawUserInfo rawUserInfo, string claimName)
    {
        if (!rawUserInfo.TryGetValue(claimName, out var element))
        {
            return null;
        }

        return element.ValueKind == JsonValueKind.Null ? null : element.GetInt64();
    }

    /// <summary>
    /// Gets an optional dictionary claim value.
    /// </summary>
    private static Dictionary<string, object>? GetOptionalDictionary(RawUserInfo rawUserInfo, string claimName)
    {
        if (!rawUserInfo.TryGetValue(claimName, out var element))
        {
            return null;
        }

        if (element.ValueKind == JsonValueKind.Null || element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var dictionary = new Dictionary<string, object>();
        foreach (var property in element.EnumerateObject())
        {
            dictionary[property.Name] = JsonElementToObject(property.Value);
        }

        return dictionary;
    }

    /// <summary>
    /// Maps the roles array from raw userinfo to UserInfoRole list.
    /// </summary>
    private static List<UserInfoRole>? MapRoles(RawUserInfo rawUserInfo)
    {
        if (!rawUserInfo.TryGetValue("roles", out var rolesElement))
        {
            return null;
        }

        if (rolesElement.ValueKind == JsonValueKind.Null || rolesElement.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var roles = new List<UserInfoRole>();
        foreach (var roleElement in rolesElement.EnumerateArray())
        {
            if (roleElement.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var id = roleElement.TryGetProperty("id", out var idProp) ? idProp.GetString() : null;
            var name = roleElement.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;

            // Try both display_name (OIDC format) and displayName (camelCase)
            string? displayName = null;
            if (roleElement.TryGetProperty("display_name", out var displayNameProp))
            {
                displayName = displayNameProp.GetString();
            }
            else if (roleElement.TryGetProperty("displayName", out var displayNameCamelProp))
            {
                displayName = displayNameCamelProp.GetString();
            }

            if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(name) || string.IsNullOrEmpty(displayName))
            {
                continue;
            }

            roles.Add(new UserInfoRole
            {
                Id = id,
                Name = name,
                DisplayName = displayName,
            });
        }

        return roles.Count > 0 ? roles : null;
    }

    /// <summary>
    /// Converts a JsonElement to its corresponding .NET object type.
    /// Numeric custom claims are exposed as long for integer literals and double for floating-point literals.
    /// </summary>
    private static object JsonElementToObject(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? string.Empty,
            JsonValueKind.Number => ParseJsonNumber(element),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null!,
            JsonValueKind.Array => element.EnumerateArray().Select(JsonElementToObject).ToList(),
            JsonValueKind.Object => element.EnumerateObject().ToDictionary(p => p.Name, p => JsonElementToObject(p.Value)),
            _ => element.ToString()!,
        };
    }

    /// <summary>
    /// Parses a JSON number into the appropriate .NET type (long for integers, double for floating-point).
    /// This ensures consistent type handling regardless of upstream JSON serialization quirks.
    /// </summary>
    private static object ParseJsonNumber(JsonElement element)
    {
        var raw = element.GetRawText();

        // Check if the raw JSON contains floating-point indicators
        if (raw.Contains('.') || raw.Contains('e') || raw.Contains('E'))
        {
            return element.GetDouble();
        }

        return element.GetInt64();
    }
}
