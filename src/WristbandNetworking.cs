using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Wristband.AspNet.Auth;

public class WristbandNetworking
{
    private readonly AuthenticationHeaderValue _basicAuthHeader;
    private readonly HttpClient _httpClient;
    private readonly string _wristbandApplicationDomain;

    // Default constructor for production (uses internal HttpClient creation)
    public WristbandNetworking(AuthConfig authConfig) : this(authConfig, null)
    {
    }

    // Constructor for testing (allows HttpClient injection)
    public WristbandNetworking(AuthConfig authConfig, HttpClient? httpClient = null)
    {
        if (authConfig == null)
        {
            throw new ArgumentNullException(nameof(authConfig), "The auth config cannot be null.");
        }

        if (string.IsNullOrWhiteSpace(authConfig.WristbandApplicationDomain))
        {
            throw new ArgumentException("The [wristbandApplicationDomain] config must have a value.");
        }

        if (string.IsNullOrWhiteSpace(authConfig.ClientId))
        {
            throw new ArgumentException("The [clientId] config must have a value.");
        }

        if (string.IsNullOrWhiteSpace(authConfig.ClientSecret))
        {
            throw new ArgumentException("The [clientSecret] config must have a value.");
        }

        _wristbandApplicationDomain = authConfig.WristbandApplicationDomain;
        _basicAuthHeader = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{authConfig.ClientId}:{authConfig.ClientSecret}")));

        _httpClient = httpClient ?? new HttpClient()
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    internal async Task<TokenResponse> GetTokens(string code, string redirectUri, string codeVerifier)
    {
        var formParams = new Dictionary<string, string>
        {
            {"grant_type", "authorization_code"},
            {"code", code},
            {"redirect_uri", redirectUri},
            {"code_verifier", codeVerifier}
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{_wristbandApplicationDomain}/api/v1/oauth2/token")
        {
            Content = new FormUrlEncodedContent(formParams)
        };

        request.Headers.Authorization = _basicAuthHeader;

        var response = await _httpClient.SendAsync(request);

        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            var errorResponseContent = await response.Content.ReadAsStringAsync();

            try
            {
                var tokenErrorResponse = JsonSerializer.Deserialize<TokenResponseError>(errorResponseContent);
                if (tokenErrorResponse == null)
                {
                    throw new InvalidOperationException("Failed to deserialize the token error response.");
                }

                if (string.Equals(tokenErrorResponse.Error, "invalid_grant", StringComparison.OrdinalIgnoreCase))
                {
                    throw new WristbandError(tokenErrorResponse.Error, tokenErrorResponse.ErrorDescription);
                }
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException("Error while parsing the token error response JSON.", ex);
            }
        }

        response.EnsureSuccessStatusCode();
        var responseContent = await response.Content.ReadAsStringAsync();

        try
        {
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent);
            if (tokenResponse == null)
            {
                throw new InvalidOperationException("Failed to deserialize the token response.");
            }

            return tokenResponse;
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Error while parsing the token response JSON.", ex);
        }
    }

    internal async Task<UserInfo> GetUserinfo(string accessToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"https://{_wristbandApplicationDomain}/api/v1/oauth2/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await _httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var responseContent = await response.Content.ReadAsStringAsync();
        return new UserInfo(responseContent);
    }

    internal async Task<TokenData> RefreshToken(string refreshToken)
    {
        var formParams = new Dictionary<string, string>
        {
            {"grant_type", "refresh_token"},
            {"refresh_token", refreshToken}
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{_wristbandApplicationDomain}/api/v1/oauth2/token")
        {
            Content = new FormUrlEncodedContent(formParams)
        };

        request.Headers.Authorization = _basicAuthHeader;

        try
        {
            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                if ((int)response.StatusCode >= 400 && (int)response.StatusCode < 500)
                {
                    throw new WristbandError("invalid_refresh_token", "Invalid Refresh Token");
                }

                if ((int)response.StatusCode >= 500)
                {
                    throw new WristbandError("unexpected_error", "Server error occurred. Retry later.");
                }
            }

            var responseContent = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent);
            return new TokenData(
                tokenResponse?.AccessToken ?? string.Empty,
                tokenResponse?.ExpiresIn ?? 0,
                tokenResponse?.IdToken ?? string.Empty,
                tokenResponse?.RefreshToken
            );
        }
        catch (WristbandError)
        {
            throw;  // Propagate custom errors (4xx and non-retryable issues)
        }
        catch (Exception)
        {
            throw new WristbandError("unexpected_error", "An unexpected error occurred during the token refresh operation.");
        }
    }

    internal async Task RevokeRefreshToken(string refreshToken)
    {
        var formParams = new Dictionary<string, string>
        {
            {"token", refreshToken}
        };

        var request = new HttpRequestMessage(HttpMethod.Post, $"https://{_wristbandApplicationDomain}/api/v1/oauth2/revoke")
        {
            Content = new FormUrlEncodedContent(formParams)
        };

        request.Headers.Authorization = _basicAuthHeader;

        try
        {
            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            // No need to block logout execution if revoking fails
            Console.Error.WriteLine($"Failed to refresh token due to: {ex.Message}\nStack Trace: {ex.StackTrace}");
        }
    }
}
