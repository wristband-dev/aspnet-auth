using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Configuration object containing URLs and settings discovered from the Wristband SDK Configuration Endpoint.
/// These values are auto-configured by calling the Wristband SDK Configuration API.
/// </summary>
internal class SdkConfiguration
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SdkConfiguration"/> class.
    /// </summary>
    public SdkConfiguration()
    {
    }

    /// <summary>
    /// Gets or sets the custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL).
    /// This value is only needed if you are self-hosting the application login page.
    /// When null, the SDK will use your Wristband-hosted Application-Level Login page URL.
    /// </summary>
    [JsonPropertyName("customApplicationLoginPageUrl")]
    public string? CustomApplicationLoginPageUrl { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether gets or sets whether your Wristband application is configured with an
    /// application-level custom domain that is active. This tells the SDK which URL format to use when constructing
    /// the Wristband Authorize Endpoint URL.
    /// </summary>
    [JsonPropertyName("isApplicationCustomDomainActive")]
    public bool IsApplicationCustomDomainActive { get; set; }

    /// <summary>
    /// Gets or sets the URL of your application's login endpoint that redirects to Wristband to initialize
    /// the login flow. If using tenant subdomains, this value must contain the `{tenant_name}` placeholder.
    /// </summary>
    [JsonPropertyName("loginUrl")]
    public string LoginUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the domain suffix used when constructing login URLs with tenant subdomains.
    /// This value is null when tenant subdomains are not being used.
    /// </summary>
    [JsonPropertyName("loginUrlTenantDomainSuffix")]
    public string? LoginUrlTenantDomainSuffix { get; set; }

    /// <summary>
    /// Gets or sets the URI that Wristband will redirect to after authenticating a user.
    /// This should point to your application's callback endpoint.
    /// If using tenant subdomains, this value must contain the `{tenant_name}` placeholder.
    /// </summary>
    [JsonPropertyName("redirectUri")]
    public string RedirectUri { get; set; } = string.Empty;
}
