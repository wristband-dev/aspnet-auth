using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Wristband;

public class WristbandNetworking
{
    private readonly HttpClient mHttpClient;
    private readonly string mWristbandApplicationDomain;
    private readonly string mClientId;
    private readonly string mClientSecret;
    private readonly string mClientIdForManagingUserMetadata;
    private readonly string mClientSecretForManagingUserMetadata;
    private string mUserMetadataToken = string.Empty;
    private DateTimeOffset mUserMetadataTokenExpiresAt = DateTimeOffset.MinValue;


    public WristbandNetworking(IHttpClientFactory httpClientFactory, AuthConfig config)
    {
        mWristbandApplicationDomain = config.WristbandApplicationDomain;
        mClientId = config.ClientId;
        mClientSecret = config.ClientSecret;
        mClientIdForManagingUserMetadata = config.ClientIdForManagingUserMetadata;
        mClientSecretForManagingUserMetadata = config.ClientSecretForManagingUserMetadata;
        mHttpClient = httpClientFactory.CreateClient("WristbandClient");
    }

    internal async Task<TokenResponse?> GetTokens(string code, string redirectUri, string codeVerifier)
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

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
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

    public async Task<UserInfo?> GetUserinfo(string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"https://{mWristbandApplicationDomain}/api/v1/oauth2/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
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
        return await response.Content.ReadFromJsonAsync<UserInfo>();
    }
    
    public async Task<UserInfo?> GetUser(string userId)
    {
        var token = await GetUserMetadataToken();
        
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        var request = new HttpRequestMessage(HttpMethod.Get, $"https://{mWristbandApplicationDomain}/api/v1/users/{userId}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
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
        return await response.Content.ReadFromJsonAsync<UserInfo>();
    }

    public async Task<bool> PatchUser(string userId, Dictionary<string, object> patchUser)
    {
        var token = await GetUserMetadataToken();
        
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }
        
        // PATCH https://application-domain.us.wristband.dev/api/v1/users/{userId}
        // {"restrictedMetadata":"{\n  \"bob\": \"your uncle\",\n  \"stuff\": [\n    \"one\",\n    \"two\",\n    \"three\"\n  ]\n}"}

        var request = new HttpRequestMessage(HttpMethod.Patch, $"https://{mWristbandApplicationDomain}/api/v1/users/{userId}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content = new StringContent(JsonSerializer.Serialize(patchUser), Encoding.UTF8, "application/json");
        var response = await mHttpClient.SendAsync(request);
        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            return false;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return false;
        }

        response.EnsureSuccessStatusCode();
        return true;
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
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
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
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{mClientId}:{mClientSecret}")));
        var response = await mHttpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    public async Task<string> GetUserMetadataToken()
    {
        if (mUserMetadataTokenExpiresAt > DateTimeOffset.UtcNow)
        {
            return mUserMetadataToken;
        }

        var url = $"https://{mWristbandApplicationDomain}/api/v1/oauth2/token";
        var authToken = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{mClientIdForManagingUserMetadata}:{mClientSecretForManagingUserMetadata}"));
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", authToken);
        request.Content = new StringContent("grant_type=client_credentials", Encoding.UTF8, "application/x-www-form-urlencoded");
        var response = await mHttpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var oAuthToken = await response.Content.ReadFromJsonAsync<OAuthTokenResponse>();
        if (oAuthToken == null)
        {
            return string.Empty;
        }

        mUserMetadataToken = oAuthToken.Access_Token;
        mUserMetadataTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(oAuthToken.Expires_In).AddSeconds(-600);
        
        return oAuthToken.Access_Token;
    }
    
    public class OAuthTokenResponse
    {
        public string Access_Token { get; set; }
        public string Token_Type { get; set; }
        public int Expires_In { get; set; }
    }
}
