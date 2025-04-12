using System.Net;
using System.Text.Json;

using Microsoft.Extensions.Options;

using Moq;
using Moq.Protected;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandApiClientTests
{
    private readonly Mock<HttpMessageHandler> _mockHttpMessageHandler;
    private readonly HttpClient _httpClient;
    private readonly IWristbandApiClient _wristbandApiClient;
    private readonly string _domain = "your-wristband-domain";

    private IOptions<WristbandAuthConfig> CreateValidOptions()
    {
        return Options.Create(new WristbandAuthConfig
        {
            WristbandApplicationDomain = _domain,
            ClientId = "test-client-id",
            ClientSecret = "test-client-secret"
        });
    }

    public WristbandApiClientTests()
    {
        _mockHttpMessageHandler = new Mock<HttpMessageHandler>();
        _httpClient = new HttpClient(_mockHttpMessageHandler.Object)
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        var mockFactory = new Mock<IHttpClientFactory>();
        mockFactory.Setup(f => f.CreateClient(It.IsAny<string>()))
            .Returns(_httpClient);

        _wristbandApiClient = new WristbandApiClient(CreateValidOptions().Value, mockFactory.Object);
    }

    // ////////////////////////////////////
    //  CONSTRUCTOR TESTS
    // ////////////////////////////////////

    [Fact]
    public void Constructor_WithValidConfig_CreatesInstance()
    {
        var apiClient = new WristbandApiClient(CreateValidOptions().Value);

        Assert.NotNull(apiClient);
    }

    [Fact]
    public void Constructor_WithNullConfig_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(() => new WristbandApiClient(null!));
        Assert.Equal("authConfig", exception.ParamName);

        exception = Assert.Throws<ArgumentNullException>(() => new WristbandApiClient(null!, null));
        Assert.Equal("authConfig", exception.ParamName);
    }

    [Theory]
    [InlineData(null, "client-id", "client-secret", "The [wristbandApplicationDomain] config must have a value.")]
    [InlineData("", "client-id", "client-secret", "The [wristbandApplicationDomain] config must have a value.")]
    [InlineData("  ", "client-id", "client-secret", "The [wristbandApplicationDomain] config must have a value.")]
    [InlineData("domain.com", null, "client-secret", "The [clientId] config must have a value.")]
    [InlineData("domain.com", "", "client-secret", "The [clientId] config must have a value.")]
    [InlineData("domain.com", "  ", "client-secret", "The [clientId] config must have a value.")]
    [InlineData("domain.com", "client-id", null, "The [clientSecret] config must have a value.")]
    [InlineData("domain.com", "client-id", "", "The [clientSecret] config must have a value.")]
    [InlineData("domain.com", "client-id", "  ", "The [clientSecret] config must have a value.")]
    public void Constructor_WithInvalidConfig_ThrowsArgumentException(string domain, string clientId, string clientSecret, string expectedMessage)
    {
        var config = new WristbandAuthConfig
        {
            WristbandApplicationDomain = domain,
            ClientId = clientId,
            ClientSecret = clientSecret
        };

        var exception = Assert.Throws<ArgumentException>(() => new WristbandApiClient(config));
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void Constructor_WithCustomHttpClientFactory_UsesProvidedFactory()
    {
        var mockFactory = new Mock<IHttpClientFactory>();
        var customClient = new HttpClient();
        mockFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(customClient);

        var apiClient = new WristbandApiClient(CreateValidOptions().Value, mockFactory.Object);

        Assert.NotNull(apiClient);
    }

    [Fact]
    public void Constructor_WithoutHttpClientFactory_CreatesNewClient()
    {
        var apiClient = new WristbandApiClient(CreateValidOptions().Value);

        Assert.NotNull(apiClient);
    }

    [Fact]
    public void Constructor_CreatesCorrectBasicAuthHeader()
    {
        // Create mock handler to capture the request
        var mockHandler = new Mock<HttpMessageHandler>();
        mockHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage(HttpStatusCode.OK));

        var client = new HttpClient(mockHandler.Object);
        var mockFactory = new Mock<IHttpClientFactory>();
        mockFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(client);

        var apiClient = new WristbandApiClient(CreateValidOptions().Value, mockFactory.Object);

        // Make a call that will use the auth header
        var result = apiClient.GetUserinfo("test-token");

        // Verify the auth header was set correctly
        mockHandler
            .Protected()
            .Verify(
                "SendAsync",
                Times.Once(),
                ItExpr.Is<HttpRequestMessage>(req =>
                    req.Headers.Authorization != null &&
                    req.Headers.Authorization.Scheme == "Bearer" &&
                    req.Headers.Authorization.Parameter == "test-token"),
                ItExpr.IsAny<CancellationToken>()
            );
    }

    // ////////////////////////////////////
    //  GET TOKENS TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task GetTokens_ValidRequest_ReturnsTokenResponse()
    {
        var code = "valid-auth-code";
        var redirectUri = "https://app.example.com/callback";
        var codeVerifier = "valid-code-verifier";

        var expectedResponse = new TokenResponse
        {
            AccessToken = "new-access-token",
            RefreshToken = "new-refresh-token",
            IdToken = "new-id-token",
            ExpiresIn = 3600
        };

        SetupTokenResponse(HttpStatusCode.OK, expectedResponse);

        var result = await _wristbandApiClient.GetTokens(code, redirectUri, codeVerifier);

        Assert.NotNull(result);
        Assert.Equal(expectedResponse.AccessToken, result.AccessToken);
        Assert.Equal(expectedResponse.RefreshToken, result.RefreshToken);
        Assert.Equal(expectedResponse.IdToken, result.IdToken);
        Assert.Equal(expectedResponse.ExpiresIn, result.ExpiresIn);

        VerifyHttpRequest(HttpMethod.Post, $"https://{_domain}/api/v1/oauth2/token", Times.Once());
    }

    [Fact]
    public async Task GetTokens_InvalidGrant_ThrowsInvalidGrantError()
    {
        var code = "invalid-auth-code";
        var redirectUri = "https://app.example.com/callback";
        var codeVerifier = "valid-code-verifier";

        var errorResponse = new TokenResponseError
        {
            Error = "invalid_grant",
            ErrorDescription = "The authorization code is invalid or has expired"
        };

        SetupHttpResponse(HttpStatusCode.BadRequest, JsonSerializer.Serialize(errorResponse));

        var exception = await Assert.ThrowsAsync<InvalidGrantError>(
            () => _wristbandApiClient.GetTokens(code, redirectUri, codeVerifier)
        );

        Assert.Equal("invalid_grant", exception.Error);
        Assert.Equal(errorResponse.ErrorDescription, exception.ErrorDescription);
    }

    [Fact]
    public async Task GetTokens_MalformedErrorResponse_ThrowsInvalidOperationException()
    {
        var code = "auth-code";
        var redirectUri = "https://app.example.com/callback";
        var codeVerifier = "code-verifier";

        SetupHttpResponse(HttpStatusCode.BadRequest, "invalid-json");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _wristbandApiClient.GetTokens(code, redirectUri, codeVerifier)
        );

        Assert.Equal("Error while parsing the token error response JSON.", exception.Message);
    }

    [Fact]
    public async Task GetTokens_NullErrorResponse_ThrowsInvalidOperationException()
    {
        var code = "auth-code";
        var redirectUri = "https://app.example.com/callback";
        var codeVerifier = "code-verifier";

        SetupHttpResponse(HttpStatusCode.BadRequest, "null");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _wristbandApiClient.GetTokens(code, redirectUri, codeVerifier)
        );

        Assert.Equal("Failed to deserialize the token error response.", exception.Message);
    }

    [Fact]
    public async Task GetTokens_ServerError_ThrowsHttpRequestException()
    {
        var code = "auth-code";
        var redirectUri = "https://app.example.com/callback";
        var codeVerifier = "code-verifier";

        SetupHttpResponse(HttpStatusCode.InternalServerError, "Server Error");

        await Assert.ThrowsAsync<HttpRequestException>(
            () => _wristbandApiClient.GetTokens(code, redirectUri, codeVerifier)
        );
    }

    [Fact]
    public async Task GetTokens_MalformedSuccessResponse_ThrowsInvalidOperationException()
    {
        var code = "valid-auth-code";
        var redirectUri = "https://app.example.com/callback";
        var codeVerifier = "valid-code-verifier";

        SetupHttpResponse(HttpStatusCode.OK, "invalid-json");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _wristbandApiClient.GetTokens(code, redirectUri, codeVerifier)
        );

        Assert.Equal("Error while parsing the token response JSON.", exception.Message);
    }

    [Fact]
    public async Task GetTokens_NullSuccessResponse_ThrowsInvalidOperationException()
    {
        var code = "valid-auth-code";
        var redirectUri = "https://app.example.com/callback";
        var codeVerifier = "valid-code-verifier";

        SetupHttpResponse(HttpStatusCode.OK, "null");

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _wristbandApiClient.GetTokens(code, redirectUri, codeVerifier)
        );

        Assert.Equal("Failed to deserialize the token response.", exception.Message);
    }

    // ////////////////////////////////////
    //  GET USERINFO TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task GetUserinfo_ValidToken_ReturnsUserInfo()
    {
        var accessToken = "valid-access-token";
        var userInfoJson = @"{
            ""sub"": ""user123"",
            ""email"": ""test@example.com"",
            ""email_verified"": true,
            ""name"": ""Test User""
        }";

        SetupHttpResponse(HttpStatusCode.OK, userInfoJson);

        var result = await _wristbandApiClient.GetUserinfo(accessToken);

        Assert.NotNull(result);

        var email = result.GetValue("email");
        Assert.Equal("test@example.com", email.GetString());

        VerifyHttpRequest(
            HttpMethod.Get,
            $"https://{_domain}/api/v1/oauth2/userinfo",
            Times.Once());
    }

    [Fact]
    public async Task GetUserinfo_InvalidToken_ThrowsHttpRequestException()
    {
        var accessToken = "invalid-access-token";
        SetupHttpResponse(HttpStatusCode.Unauthorized, "Unauthorized");

        await Assert.ThrowsAsync<HttpRequestException>(
            () => _wristbandApiClient.GetUserinfo(accessToken)
        );
    }

    [Fact]
    public async Task GetUserinfo_ServerError_ThrowsHttpRequestException()
    {
        var accessToken = "valid-access-token";
        SetupHttpResponse(HttpStatusCode.InternalServerError, "Internal Server Error");

        await Assert.ThrowsAsync<HttpRequestException>(
            () => _wristbandApiClient.GetUserinfo(accessToken)
        );
    }

    [Fact]
    public async Task GetUserinfo_NetworkError_ThrowsHttpRequestException()
    {
        var accessToken = "valid-access-token";
        _mockHttpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Network error"));

        await Assert.ThrowsAsync<HttpRequestException>(
            () => _wristbandApiClient.GetUserinfo(accessToken)
        );
    }

    [Fact]
    public async Task GetUserinfo_InvalidJsonResponse_ThrowsInvalidOperationException()
    {
        var accessToken = "valid-access-token";
        SetupHttpResponse(HttpStatusCode.OK, "invalid-json-content");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _wristbandApiClient.GetUserinfo(accessToken)
        );
    }

    [Fact]
    public async Task GetUserinfo_EmptyResponse_ThrowsArgumentException()
    {
        var accessToken = "valid-access-token";
        SetupHttpResponse(HttpStatusCode.OK, "");

        await Assert.ThrowsAsync<ArgumentException>(
            () => _wristbandApiClient.GetUserinfo(accessToken)
        );
    }

    // ////////////////////////////////////
    //  REFRESH TOKEN TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task RefreshToken_ValidToken_ReturnsTokenData()
    {
        var refreshToken = "valid-refresh-token";
        var expectedResponse = new TokenResponse
        {
            AccessToken = "new-access-token",
            RefreshToken = "new-refresh-token",
            IdToken = "new-id-token",
            ExpiresIn = 3600
        };

        SetupTokenResponse(HttpStatusCode.OK, expectedResponse);

        var result = await _wristbandApiClient.RefreshToken(refreshToken);

        Assert.NotNull(result);
        Assert.Equal(expectedResponse.AccessToken, result.AccessToken);
        Assert.Equal(expectedResponse.RefreshToken, result.RefreshToken);
        Assert.Equal(expectedResponse.IdToken, result.IdToken);
        Assert.Equal(expectedResponse.ExpiresIn, result.ExpiresIn);

        VerifyHttpRequest(HttpMethod.Post, $"https://{_domain}/api/v1/oauth2/token", Times.Once());
    }

    [Fact]
    public async Task RefreshToken_InvalidToken_ThrowsWristbandError()
    {
        var refreshToken = "invalid-refresh-token";
        SetupTokenResponse(HttpStatusCode.BadRequest, null);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => _wristbandApiClient.RefreshToken(refreshToken));

        Assert.Equal("invalid_refresh_token", exception.Error);
        Assert.Equal("Invalid Refresh Token", exception.ErrorDescription);
    }

    [Fact]
    public async Task RefreshToken_ServerError_ThrowsWristbandError()
    {
        var refreshToken = "valid-refresh-token";
        SetupTokenResponse(HttpStatusCode.InternalServerError, null);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => _wristbandApiClient.RefreshToken(refreshToken));

        Assert.Equal("unexpected_error", exception.Error);
        Assert.Equal("Server error occurred. Retry later.", exception.ErrorDescription);
    }

    [Fact]
    public async Task RefreshToken_NetworkError_ThrowsWristbandError()
    {
        var refreshToken = "valid-refresh-token";
        _mockHttpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Network error"));

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => _wristbandApiClient.RefreshToken(refreshToken));

        Assert.Equal("unexpected_error", exception.Error);
        Assert.Equal("An unexpected error occurred during the token refresh operation.", exception.ErrorDescription);
    }

    // ////////////////////////////////////
    //  REVOKE REFRESH TOKEN TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task RevokeRefreshToken_ValidToken_Succeeds()
    {
        var refreshToken = "valid-refresh-token";
        SetupTokenResponse(HttpStatusCode.OK, null);

        await _wristbandApiClient.RevokeRefreshToken(refreshToken);

        VerifyHttpRequest(HttpMethod.Post, $"https://{_domain}/api/v1/oauth2/revoke", Times.Once());
    }

    [Fact]
    public async Task RevokeRefreshToken_ServerError_LogsError()
    {
        var refreshToken = "valid-refresh-token";
        SetupTokenResponse(HttpStatusCode.InternalServerError, null);

        var stringWriter = new StringWriter();
        Console.SetError(stringWriter);

        await _wristbandApiClient.RevokeRefreshToken(refreshToken);

        var errorLogs = stringWriter.ToString();
        Assert.Contains("Failed to refresh token due to:", errorLogs);

        VerifyHttpRequest(HttpMethod.Post, $"https://{_domain}/api/v1/oauth2/revoke", Times.Once());
    }

    [Fact]
    public async Task RevokeRefreshToken_NetworkError_LogsError()
    {
        var refreshToken = "valid-refresh-token";
        _mockHttpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("Network error"));

        var stringWriter = new StringWriter();
        Console.SetError(stringWriter);

        await _wristbandApiClient.RevokeRefreshToken(refreshToken);

        var errorLogs = stringWriter.ToString();
        Assert.Contains("Failed to refresh token due to:", errorLogs);

        VerifyHttpRequest(HttpMethod.Post, $"https://{_domain}/api/v1/oauth2/revoke", Times.Once());
    }

    // ////////////////////////////////////
    //  PRIVATE TEST METHODS
    // ////////////////////////////////////

    private void SetupHttpResponse(HttpStatusCode statusCode, string content)
    {
        var httpResponse = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(content)
        };

        _mockHttpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(httpResponse);
    }

    private void SetupTokenResponse(HttpStatusCode statusCode, TokenResponse? response)
    {
        var content = response != null ? JsonSerializer.Serialize(response) : string.Empty;
        var httpResponse = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(content)
        };

        _mockHttpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(httpResponse);
    }

    private void VerifyHttpRequest(HttpMethod method, string url, Times times)
    {
        _mockHttpMessageHandler
            .Protected()
            .Verify(
                "SendAsync",
                times,
                ItExpr.Is<HttpRequestMessage>(req =>
                    req.Method == method &&
                    req.RequestUri != null &&
                    req.RequestUri.ToString() == url),
                ItExpr.IsAny<CancellationToken>()
            );
    }
}
