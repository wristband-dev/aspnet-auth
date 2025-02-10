using System.Text.Json.Serialization;

namespace Wristband.AspNet.Auth;

internal class LoginState
{
    public string CodeVerifier { get; set; }
    public Dictionary<string, object>? CustomState { get; set; }
    public string RedirectUri { get; set; }
    public string? ReturnUrl { get; set; }
    public string State { get; set; }

    public LoginState(
        string state,
        string codeVerifier,
        string redirectUri,
        string returnUrl,
        Dictionary<string, object>? customState
    )
    {
        if (string.IsNullOrEmpty(state))
        {
            throw new InvalidOperationException("[State] cannot be null or empty.");
        }
        if (string.IsNullOrEmpty(codeVerifier))
        {
            throw new InvalidOperationException("[CodeVerifier] cannot be null or empty.");
        }
        if (string.IsNullOrEmpty(redirectUri))
        {
            throw new InvalidOperationException("[RedirectUri] cannot be null or empty.");
        }

        State = state;
        CodeVerifier = codeVerifier;
        RedirectUri = redirectUri;
        ReturnUrl = returnUrl;
        CustomState = customState;
    }
}

internal class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; } = 0;

    [JsonPropertyName("id_token")]
    public string IdToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = string.Empty;

    public TokenResponse() { }
}

internal class TokenResponseError
{
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; } = string.Empty;

    public TokenResponseError() { }
}
