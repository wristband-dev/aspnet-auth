using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using Microsoft.Extensions.DependencyInjection;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Contains all code for making REST API calls to the Wristband platform.
/// </summary>
internal class WristbandApiClient : IWristbandApiClient
{
    // Default timeout for HTTP requests in seconds
    private const int DefaultTimeoutSeconds = 30;

    // Lazy-initialized HTTP client factory instance
    private static readonly Lazy<IHttpClientFactory> _internalFactory = new Lazy<IHttpClientFactory>(() =>
        CreateInternalFactory());

    private readonly AuthenticationHeaderValue _basicAuthHeader;
    private readonly string _clientId;
    private readonly HttpClient _httpClient;
    private readonly string _wristbandApplicationVanityDomain;

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandApiClient"/> class for production use.
    /// </summary>
    /// <param name="authConfig">The <see cref="WristbandAuthConfig"/> containing the necessary credentials and domain for the Wristband application.</param>
    internal WristbandApiClient(WristbandAuthConfig authConfig)
        : this(authConfig, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandApiClient"/> class.
    /// This constructor is useful for testing, allowing the injection of a custom <see cref="HttpClient"/>.
    /// </summary>
    /// <param name="authConfig">The <see cref="WristbandAuthConfig"/> containing the necessary credentials and domain for the Wristband application.</param>
    /// <param name="externalFactory">Optional external HTTP client factory. If not provided, an internal factory will be used.</param>
    internal WristbandApiClient(WristbandAuthConfig authConfig, IHttpClientFactory? externalFactory = null)
    {
        if (authConfig == null)
        {
            throw new ArgumentNullException(nameof(authConfig), "The auth config cannot be null.");
        }

        if (string.IsNullOrWhiteSpace(authConfig.WristbandApplicationVanityDomain))
        {
            throw new ArgumentException("The [WristbandApplicationVanityDomain] config must have a value.");
        }

        if (string.IsNullOrWhiteSpace(authConfig.ClientId))
        {
            throw new ArgumentException("The [ClientId] config must have a value.");
        }

        if (string.IsNullOrWhiteSpace(authConfig.ClientSecret))
        {
            throw new ArgumentException("The [ClientSecret] config must have a value.");
        }

        _wristbandApplicationVanityDomain = authConfig.WristbandApplicationVanityDomain;
        _clientId = authConfig.ClientId;
        _basicAuthHeader = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{authConfig.ClientId}:{authConfig.ClientSecret}")));

        // Use the provided factory, or fall back to internal one
        var factory = externalFactory ?? _internalFactory.Value;
        _httpClient = factory.CreateClient("WristbandAuth");
    }

    /// <summary>
    /// Implements <see cref="IWristbandApiClient.GetTokens"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<SdkConfiguration> GetSdkConfiguration()
    {
        return await WristbandApiRetry.WithRetry(async () =>
        {
            var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"https://{_wristbandApplicationVanityDomain}/api/v1/clients/{_clientId}/sdk-configuration");

            request.Headers.Add("Accept", "application/json");

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();

            var sdkConfig = JsonSerializer.Deserialize<SdkConfiguration>(responseContent);
            if (sdkConfig == null)
            {
                throw new InvalidOperationException("Failed to deserialize SDK configuration response");
            }

            return sdkConfig;
        });
    }

    /// <summary>
    /// Implements <see cref="IWristbandApiClient.GetTokens"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<WristbandTokenResponse> GetTokens(string code, string redirectUri, string codeVerifier)
    {
        var formParams = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", redirectUri },
            { "code_verifier", codeVerifier },
        };

        return await WristbandApiRetry.WithRetry(async () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, $"https://{_wristbandApplicationVanityDomain}/api/v1/oauth2/token")
            {
                Content = new FormUrlEncodedContent(formParams),
            };

            request.Headers.Authorization = _basicAuthHeader;

            var response = await _httpClient.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                var errorResponseContent = await response.Content.ReadAsStringAsync();
                var tokenErrorResponse = TryParseTokenErrorResponse(errorResponseContent);

                if (tokenErrorResponse != null &&
                    string.Equals(tokenErrorResponse.Error, "invalid_grant", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidGrantError(tokenErrorResponse.ErrorDescription);
                }

                // Any other 400 falls through to EnsureSuccessStatusCode() below so that the HTTP
                // failure itself surfaces. A 400 whose body is not the expected JSON (for example an
                // HTML error page from a proxy or CDN) would otherwise be reported as a parse error,
                // hiding the real status code.
            }

            response.EnsureSuccessStatusCode();
            var responseContent = await response.Content.ReadAsStringAsync();

            try
            {
                var tokenResponse = JsonSerializer.Deserialize<WristbandTokenResponse>(responseContent);
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
        });
    }

    /// <summary>
    /// Implements <see cref="IWristbandApiClient.GetUserinfo"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<UserInfo> GetUserinfo(string accessToken)
    {
        return await WristbandApiRetry.WithRetry(async () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"https://{_wristbandApplicationVanityDomain}/api/v1/oauth2/userinfo");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();

            // Parse raw OIDC claims
            var rawUserInfo = new RawUserInfo(responseContent);

            // Map to friendly UserInfo
            return UserInfoMapper.MapUserInfo(rawUserInfo);
        });
    }

    /// <summary>
    /// Implements <see cref="IWristbandApiClient.RefreshToken"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<WristbandTokenResponse> RefreshToken(string refreshToken)
    {
        var formParams = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", refreshToken },
        };

        return await WristbandApiRetry.WithRetry(async () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, $"https://{_wristbandApplicationVanityDomain}/api/v1/oauth2/token")
            {
                Content = new FormUrlEncodedContent(formParams),
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
                var tokenResponse = JsonSerializer.Deserialize<WristbandTokenResponse>(responseContent);

                if (tokenResponse == null)
                {
                    throw new InvalidOperationException("Failed to deserialize token response.");
                }

                return tokenResponse;
            }
            catch (WristbandError)
            {
                throw;  // Propagate custom errors (4xx and non-retryable issues)
            }
            catch (Exception)
            {
                throw new WristbandError("unexpected_error", "An unexpected error occurred during the token refresh operation.");
            }
        });
    }

    /// <summary>
    /// Implements <see cref="IWristbandApiClient.RevokeRefreshToken"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task RevokeRefreshToken(string refreshToken)
    {
        var formParams = new Dictionary<string, string>
        {
            { "token", refreshToken },
        };

        try
        {
            await WristbandApiRetry.WithRetry(async () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Post, $"https://{_wristbandApplicationVanityDomain}/api/v1/oauth2/revoke")
                {
                    Content = new FormUrlEncodedContent(formParams),
                };

                request.Headers.Authorization = _basicAuthHeader;

                var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();
            });
        }
        catch (Exception)
        {
            // Ignore revoke errors; logout should still succeed
        }
    }

    /// <summary>
    /// Implements <see cref="IWristbandApiClient.ValidateTenantCustomDomain"/>.
    /// </summary>
    /// <inheritdoc />
    public async Task<bool> ValidateTenantCustomDomain(string tenantCustomDomain)
    {
        if (string.IsNullOrWhiteSpace(tenantCustomDomain))
        {
            throw new ArgumentException("The tenant custom domain must have a value.", nameof(tenantCustomDomain));
        }

        var payload = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            { "tenantCustomDomain", tenantCustomDomain },
        });

        return await WristbandApiRetry.WithRetry(async () =>
        {
            var request = new HttpRequestMessage(
                HttpMethod.Post,
                $"https://{_wristbandApplicationVanityDomain}/api/v1/custom-domains/validate")
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json"),
            };

            request.Headers.Add("Accept", "application/json");
            request.Headers.Authorization = _basicAuthHeader;

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync();

            try
            {
                var validationResponse = JsonSerializer.Deserialize<ValidateTenantCustomDomainResponse>(responseContent);
                if (validationResponse == null)
                {
                    throw new InvalidOperationException("Failed to deserialize the tenant custom domain validation response.");
                }

                return validationResponse.Valid;
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException("Error while parsing the tenant custom domain validation response JSON.", ex);
            }
        });
    }

    /// <summary>
    /// Deserializes a token error response body, returning null when the body is not the expected JSON.
    /// </summary>
    /// <param name="errorResponseContent">The raw response body.</param>
    /// <returns>The parsed error response, or null if the body could not be parsed.</returns>
    private static WristbandTokenResponseError? TryParseTokenErrorResponse(string errorResponseContent)
    {
        try
        {
            return JsonSerializer.Deserialize<WristbandTokenResponseError>(errorResponseContent);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Creates an internal HTTP client factory for API requests.
    /// This allows the class to create and configure HTTP clients without external dependencies.
    /// </summary>
    /// <returns>An HTTP client factory configured for Wristband API requests.</returns>
    private static IHttpClientFactory CreateInternalFactory()
    {
        var services = new ServiceCollection();
        services.AddHttpClient("WristbandAuth", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(DefaultTimeoutSeconds);
        });
        var serviceProvider = services.BuildServiceProvider();
        return serviceProvider.GetRequiredService<IHttpClientFactory>();
    }
}
