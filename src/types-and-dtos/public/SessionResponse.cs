using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Response model for session endpoints, matching the format expected by Wristband frontend SDKs.
/// </summary>
public class SessionResponse
{
    /// <summary>
    /// Gets the ID of the authenticated user.
    /// </summary>
    [JsonPropertyName("userId")]
    public required string UserId { get; init; }

    /// <summary>
    /// Gets the ID of the tenant that the authenticated user belongs to.
    /// </summary>
    [JsonPropertyName("tenantId")]
    public required string TenantId { get; init; }

    /// <summary>
    /// Gets the optional custom metadata. Can contain any JSON-serializable data.
    /// </summary>
    [JsonPropertyName("metadata")]
    public object? Metadata { get; init; }
}
