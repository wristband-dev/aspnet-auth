using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents a role assigned to a user in Wristband.
/// This is a subset of fields from the Role entity in Wristband's Resource Management API.
/// </summary>
public class UserInfoRole
{
    /// <summary>
    /// Gets the globally unique ID of the role.
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; init; }

    /// <summary>
    /// Gets the role name (e.g., "app:app-name:admin").
    /// </summary>
    [JsonPropertyName("name")]
    public required string Name { get; init; }

    /// <summary>
    /// Gets the human-readable display name for the role.
    /// </summary>
    [JsonPropertyName("displayName")]
    public required string DisplayName { get; init; }
}
