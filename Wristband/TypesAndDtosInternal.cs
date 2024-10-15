using System.Text.Json.Serialization;

namespace Wristband;

// Types and DTOs

internal class LoginState
{
    public string State { get; set; }
    public string CodeVerifier { get; set; }
    public string RedirectUri { get; set; }
    public string TenantDomainName { get; set; }
    public string ReturnUrl { get; set; }
    public dynamic? CustomState { get; set; }
}

internal class LoginStateMapConfig
{
    public string TenantDomainName { get; set; }
    public dynamic? CustomState { get; set; }
}

internal class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("id_token")]
    public string IdToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; }

    [JsonPropertyName("scope")]
    public string Scope { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }
}
