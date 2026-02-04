using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Response model for token endpoints, matching the format expected by Wristband frontend SDKs.
/// </summary>
public class TokenResponse
{
    /// <summary>
    /// Gets the access token for making authenticated API requests.
    /// </summary>
    [JsonPropertyName("accessToken")]
    public required string AccessToken { get; init; }

    /// <summary>
    /// Gets the absolute expiration time of the access token in milliseconds since Unix epoch.
    /// </summary>
    [JsonPropertyName("expiresAt")]
    public required long ExpiresAt { get; init; }
}
