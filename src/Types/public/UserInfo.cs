using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// User Info model representing claims from the Wristband UserInfo endpoint.
/// This model represents user information returned from Wristband's OIDC-compliant
/// UserInfo endpoint, with field names mapped to match the User entity field names
/// in Wristband's Resource Management API. The claims returned depend on the scopes
/// requested during authorization.
/// </summary>
/// <remarks>
/// Always returned claims: UserId, TenantId, ApplicationId, IdentityProviderName
///
/// Scope-dependent claims:
/// - profile: FullName, GivenName, FamilyName, MiddleName, Nickname, DisplayName,
///            PictureUrl, Gender, Birthdate, TimeZone, Locale, UpdatedAt
/// - email: Email, EmailVerified
/// - phone: PhoneNumber, PhoneNumberVerified
/// - roles: Roles.
/// </remarks>
/// <example>
/// <code>
/// {
///   "userId": "x25rpgafgvgedcvjw52ooul3xm",
///   "tenantId": "lu4a47jcm2ejayovsgbgbpkihb",
///   "applicationId": "hblu4a47jcm2ejayovsgbgbpki",
///   "identityProviderName": "Wristband",
///   "fullName": "Bob Jay Smith",
///   "givenName": "Bob",
///   "familyName": "Smith",
///   "email": "bob@example.com",
///   "emailVerified": true,
///   "roles": [
///     {
///       "id": "x25rpgafgvgedcvjw52oool3xm",
///       "name": "app:app-name:admin",
///       "displayName": "Admin Role"
///     }
///   ],
///   "customClaims": {
///     "fieldA": "a",
///     "fieldB": "b"
///   }
/// }
/// </code>
/// </example>
public class UserInfo
{
    /// <summary>
    /// Gets an empty instance of the <see cref="UserInfo"/> class with default empty data.
    /// </summary>
    public static readonly UserInfo Empty = new UserInfo
    {
        UserId = string.Empty,
        TenantId = string.Empty,
        ApplicationId = string.Empty,
        IdentityProviderName = string.Empty,
    };

    // ========================================
    // ALWAYS RETURNED - MAPPED FROM OIDC STANDARD CLAIMS
    // ========================================

    /// <summary>
    /// Gets the ID of the user (mapped from "sub" claim).
    /// </summary>
    [JsonPropertyName("userId")]
    public required string UserId { get; init; }

    /// <summary>
    /// Gets the ID of the tenant that the user belongs to (mapped from "tnt_id" claim).
    /// </summary>
    [JsonPropertyName("tenantId")]
    public required string TenantId { get; init; }

    /// <summary>
    /// Gets the ID of the application that the user belongs to (mapped from "app_id" claim).
    /// </summary>
    [JsonPropertyName("applicationId")]
    public required string ApplicationId { get; init; }

    /// <summary>
    /// Gets the name of the identity provider (mapped from "idp_name" claim).
    /// </summary>
    [JsonPropertyName("identityProviderName")]
    public required string IdentityProviderName { get; init; }

    // ========================================
    // PROFILE SCOPE - MAPPED TO USER ENTITY FIELD NAMES
    // ========================================

    /// <summary>
    /// Gets the end-user's full name in displayable form (mapped from "name" claim).
    /// </summary>
    [JsonPropertyName("fullName")]
    public string? FullName { get; init; }

    /// <summary>
    /// Gets the given name(s) or first name(s) of the end-user.
    /// </summary>
    [JsonPropertyName("givenName")]
    public string? GivenName { get; init; }

    /// <summary>
    /// Gets the surname(s) or last name(s) of the end-user.
    /// </summary>
    [JsonPropertyName("familyName")]
    public string? FamilyName { get; init; }

    /// <summary>
    /// Gets the middle name(s) of the end-user.
    /// </summary>
    [JsonPropertyName("middleName")]
    public string? MiddleName { get; init; }

    /// <summary>
    /// Gets the casual name of the end-user.
    /// </summary>
    [JsonPropertyName("nickname")]
    public string? Nickname { get; init; }

    /// <summary>
    /// Gets the shorthand name by which the end-user wishes to be referred (mapped from "preferred_username").
    /// </summary>
    [JsonPropertyName("displayName")]
    public string? DisplayName { get; init; }

    /// <summary>
    /// Gets the URL of the end-user's profile picture (mapped from "picture").
    /// </summary>
    [JsonPropertyName("pictureUrl")]
    public string? PictureUrl { get; init; }

    /// <summary>
    /// Gets the end-user's gender.
    /// </summary>
    [JsonPropertyName("gender")]
    public string? Gender { get; init; }

    /// <summary>
    /// Gets the end-user's birthday in YYYY-MM-DD format.
    /// </summary>
    [JsonPropertyName("birthdate")]
    public string? Birthdate { get; init; }

    /// <summary>
    /// Gets the end-user's time zone (mapped from "zoneinfo").
    /// </summary>
    [JsonPropertyName("timeZone")]
    public string? TimeZone { get; init; }

    /// <summary>
    /// Gets the end-user's locale as BCP47 language tag (e.g., "en-US").
    /// </summary>
    [JsonPropertyName("locale")]
    public string? Locale { get; init; }

    /// <summary>
    /// Gets the time when the user's information was last updated.
    /// The value is represented as the number of seconds from the Unix epoch.
    /// </summary>
    [JsonPropertyName("updatedAt")]
    public long? UpdatedAt { get; init; }

    // ========================================
    // EMAIL SCOPE
    // ========================================

    /// <summary>
    /// Gets the end-user's preferred email address.
    /// </summary>
    [JsonPropertyName("email")]
    public string? Email { get; init; }

    /// <summary>
    /// Gets a value indicating whether the end-user's email address has been verified.
    /// </summary>
    [JsonPropertyName("emailVerified")]
    public bool? EmailVerified { get; init; }

    // ========================================
    // PHONE SCOPE
    // ========================================

    /// <summary>
    /// Gets the end-user's telephone number in E.164 format.
    /// </summary>
    [JsonPropertyName("phoneNumber")]
    public string? PhoneNumber { get; init; }

    /// <summary>
    /// Gets a value indicating whether the end-user's phone number has been verified.
    /// </summary>
    [JsonPropertyName("phoneNumberVerified")]
    public bool? PhoneNumberVerified { get; init; }

    // ========================================
    // ROLES SCOPE
    // ========================================

    /// <summary>
    /// Gets the roles assigned to the user.
    /// </summary>
    [JsonPropertyName("roles")]
    public List<UserInfoRole>? Roles { get; init; }

    // ========================================
    // CUSTOM CLAIMS
    // ========================================

    /// <summary>
    /// Gets the object containing any configured custom claims.
    /// </summary>
    [JsonPropertyName("customClaims")]
    public Dictionary<string, object>? CustomClaims { get; init; }
}
