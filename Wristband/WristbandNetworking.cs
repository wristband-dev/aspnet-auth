using System.Net;
using System.Net.Http.Json;

namespace Wristband;

internal class WristbandNetworking
{
    private readonly HttpClient mHttpClient;
    private readonly string mWristbandApplicationDomain;
    private readonly string mClientId;
    private readonly string mClientSecret;

    public WristbandNetworking(IHttpClientFactory httpClientFactory, AuthConfig config)
    {
        mWristbandApplicationDomain = config.WristbandApplicationDomain;
        mClientId = config.ClientId;
        mClientSecret = config.ClientSecret;
        mHttpClient = httpClientFactory.CreateClient("WristbandClient");
    }

    public async Task<TokenResponse?> GetTokens(string code, string redirectUri, string codeVerifier)
    {
        var formParams = new Dictionary<string, string>
        {
            {"grant_type", "authorization_code"},
            {"code", code},
            {"redirect_uri", redirectUri},
            {"code_verifier", codeVerifier}
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{mWristbandApplicationDomain}/api/v1/oauth2/token") {
            Content = new FormUrlEncodedContent(formParams)
        };

        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{mClientId}:{mClientSecret}")));
        var response = await mHttpClient.SendAsync(request);
        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            return null;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<TokenResponse>();
    }

    public async Task<Userinfo?> GetUserinfo(string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"https://{mWristbandApplicationDomain}/api/v1/oauth2/userinfo");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        var response = await mHttpClient.SendAsync(request);
        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            return null;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<Userinfo>();
    }

    public async Task<TokenData> RefreshToken(string refreshToken)
    {
        var formParams = new Dictionary<string, string>
        {
            {"grant_type", "refresh_token"},
            {"refresh_token", refreshToken}
        };
        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{mWristbandApplicationDomain}/api/v1/oauth2/token")
        {
            Content = new FormUrlEncodedContent(formParams)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{mClientId}:{mClientSecret}")));
        var response = await mHttpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

        return new TokenData()
        {
            AccessToken = tokenResponse?.AccessToken ?? string.Empty,
            IdToken = tokenResponse?.IdToken ?? string.Empty,
            RefreshToken = tokenResponse?.RefreshToken ?? string.Empty,
            ExpiresIn = tokenResponse?.ExpiresIn ?? 0,
        };
    }

    public async Task RevokeRefreshToken(string refreshToken)
    {
        var formParams = new Dictionary<string, string>
        {
            {"token", refreshToken}
        };
        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{mWristbandApplicationDomain}/api/v1/oauth2/revoke") {
            Content = new FormUrlEncodedContent(formParams)
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{mClientId}:{mClientSecret}")));
        var response = await mHttpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }
}
