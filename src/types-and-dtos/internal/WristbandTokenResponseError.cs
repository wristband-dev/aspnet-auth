using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the error response received from the Wristband Token Endpoint in case of a failure.
/// </summary>
internal class WristbandTokenResponseError
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandTokenResponseError"/> class.
    /// </summary>
    public WristbandTokenResponseError()
    {
    }

    /// <summary>
    /// Gets or sets the error code describing the failure.
    /// </summary>
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the error description, providing more details about the failure. This property is optional.
    /// </summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; } = string.Empty;
}
