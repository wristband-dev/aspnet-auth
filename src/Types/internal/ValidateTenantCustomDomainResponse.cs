using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the response received from the Wristband Tenant Custom Domain Validation Endpoint.
/// </summary>
internal class ValidateTenantCustomDomainResponse
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ValidateTenantCustomDomainResponse"/> class.
    /// </summary>
    public ValidateTenantCustomDomainResponse()
    {
    }

    /// <summary>
    /// Gets or sets a value indicating whether the tenant custom domain is verified and belongs to your Wristband application.
    /// </summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }
}
