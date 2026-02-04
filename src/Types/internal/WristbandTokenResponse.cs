using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the token response received from the Wristband Token Endpoint.
/// </summary>
internal class WristbandTokenResponse
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandTokenResponse"/> class.
    /// </summary>
    public WristbandTokenResponse()
    {
    }

    /// <summary>
    /// Gets or sets the access token.
    /// </summary>
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the expiration time of the access token (in seconds).
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; } = 0;

    /// <summary>
    /// Gets or sets the ID token.
    /// </summary>
    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the refresh token. This property is optional.
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    /// <summary>
    /// Gets or sets the scope of the token.
    /// </summary>
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the type of token.
    /// </summary>
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = string.Empty;
}
