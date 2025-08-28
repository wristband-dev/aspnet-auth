using System.Reflection;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class RefreshTokenIfExpiredTests
{
    private readonly Mock<IWristbandApiClient> _mockApiClient = new Mock<IWristbandApiClient>();

    private readonly WristbandAuthService _wristbandAuthService;
    private readonly WristbandAuthConfig _authConfig;

    public RefreshTokenIfExpiredTests()
    {
        _authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            DangerouslyDisableSecureCookies = false,
            LoginStateSecret = new string('a', 32),
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback",
            WristbandApplicationVanityDomain = "example.com",
            IsApplicationCustomDomainActive = false,
        };

        _wristbandAuthService = new WristbandAuthService(_authConfig);

        // Use reflection to inject the mock API Client object into the service
        var fieldInfo = typeof(WristbandAuthService).GetField("mWristbandApiClient", BindingFlags.NonPublic | BindingFlags.Instance);
        if (fieldInfo != null && _mockApiClient != null)
        {
            fieldInfo.SetValue(_wristbandAuthService, _mockApiClient.Object);
        }
    }

    [Fact]
    public async Task RefreshTokenIfExpired_NullRefreshToken_ThrowsArgumentException()
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => _wristbandAuthService.RefreshTokenIfExpired(null!, 1));

        Assert.Equal("Refresh token must be a valid string", exception.Message);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_EmptyRefreshToken_ThrowsArgumentException()
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => _wristbandAuthService.RefreshTokenIfExpired("", 1));

        Assert.Equal("Refresh token must be a valid string", exception.Message);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_ZeroExpiresAt_ThrowsArgumentException()
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => _wristbandAuthService.RefreshTokenIfExpired("valid-token", 0));

        Assert.Equal("The expiresAt field must be a positive integer", exception.Message);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_NegativeExpiresAt_ThrowsArgumentException()
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(
            () => _wristbandAuthService.RefreshTokenIfExpired("valid-token", -1));

        Assert.Equal("The expiresAt field must be a positive integer", exception.Message);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_Should_NotRefresh_When_AccessTokenValid()
    {
        var dateTime = DateTime.UtcNow.AddMinutes(10);
        var msSinceEpoch = new DateTimeOffset(dateTime).ToUnixTimeMilliseconds();

        var result = await _wristbandAuthService.RefreshTokenIfExpired("validRefreshToken", msSinceEpoch);

        Assert.Null(result);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_Should_RefreshToken_When_AccessTokenExpired()
    {
        // Create expected token response using property initialization
        var expectedTokenResponse = new TokenResponse
        {
            AccessToken = "newAccessToken",
            ExpiresIn = 3600,
            IdToken = "newIdToken",
            RefreshToken = "newRefreshToken"
        };

        _mockApiClient
            .Setup(m => m.RefreshToken("validRefreshToken"))
            .ReturnsAsync(expectedTokenResponse);

        var dateTime = DateTime.UtcNow.AddMinutes(-5);
        var msSinceEpoch = new DateTimeOffset(dateTime).ToUnixTimeMilliseconds();

        var result = await _wristbandAuthService.RefreshTokenIfExpired("validRefreshToken", msSinceEpoch);

        Assert.NotNull(result);
        Assert.Equal("newAccessToken", result.AccessToken);
        Assert.True(result.ExpiresAt > 0); // Should be set by the service logic
        Assert.Equal(3540, result.ExpiresIn); // 3600 - 60 (token expiration buffer)
        Assert.Equal("newIdToken", result.IdToken);
        Assert.Equal("newRefreshToken", result.RefreshToken);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_InvalidRefreshToken_ThrowsWristbandError()
    {
        // Redirect Console.WriteLine output to a StringWriter to suppress console output
        var originalOutput = Console.Out;
        using (var writer = new StringWriter())
        {
            Console.SetOut(writer);

            try
            {
                _mockApiClient
                    .Setup(m => m.RefreshToken("invalidRefreshToken"))
                    .ThrowsAsync(new WristbandError("invalid_refresh_token", "Invalid Refresh Token"));

                var dateTime = DateTime.UtcNow.AddMinutes(-5);
                var msSinceEpoch = new DateTimeOffset(dateTime).ToUnixTimeMilliseconds();

                var exception = await Assert.ThrowsAsync<WristbandError>(
                    () => _wristbandAuthService.RefreshTokenIfExpired("invalidRefreshToken", msSinceEpoch)
                );

                Assert.NotNull(exception);
                Assert.Equal("invalid_refresh_token", exception.Error);
                Assert.Equal("Invalid Refresh Token", exception.ErrorDescription);
            }
            finally
            {
                // Restore the original console output
                Console.SetOut(originalOutput);
            }
        }
    }

    [Fact]
    public async Task RefreshTokenIfExpired_ServerError_RetryAndSucceed()
    {
        // Setup to fail with error once, then succeed
        _mockApiClient
            .SetupSequence(m => m.RefreshToken("validRefreshToken"))
            .ThrowsAsync(new WristbandError("unexpected_error", "Unexpected Error"))
            .ReturnsAsync(new TokenResponse
            {
                AccessToken = "newAccessToken",
                ExpiresIn = 3600,
                IdToken = "newIdToken",
                RefreshToken = "newRefreshToken"
            });

        var dateTime = DateTime.UtcNow.AddMinutes(-5);
        var msSinceEpoch = new DateTimeOffset(dateTime).ToUnixTimeMilliseconds();

        var result = await _wristbandAuthService.RefreshTokenIfExpired("validRefreshToken", msSinceEpoch);

        Assert.NotNull(result);
        Assert.Equal("newAccessToken", result.AccessToken);
        Assert.True(result.ExpiresAt > 0);
        Assert.Equal(3540, result.ExpiresIn); // 3600 - 60 (token expiration buffer)
        Assert.Equal("newIdToken", result.IdToken);
        Assert.Equal("newRefreshToken", result.RefreshToken);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_ServerError_ExhaustsRetries()
    {
        _mockApiClient
            .Setup(m => m.RefreshToken("validRefreshToken"))
            .ThrowsAsync(new Exception("Some error"));

        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);

        var dateTime = DateTime.UtcNow.AddMinutes(-5);
        var msSinceEpoch = new DateTimeOffset(dateTime).ToUnixTimeMilliseconds();

        var exception = await Assert.ThrowsAsync<Exception>(
            () => _wristbandAuthService.RefreshTokenIfExpired("validRefreshToken", msSinceEpoch)
        );

        Assert.NotNull(exception);
        Assert.Equal("Some error", exception.Message);

        var output = stringWriter.ToString();
        Assert.Contains("Attempt 3 failed. Aborting...", output);
    }

    [Fact]
    public async Task RefreshTokenIfExpired_VerifyExpiresAtCalculation()
    {
        // Test that ExpiresAt is calculated correctly by the service
        var mockTokenResponse = new TokenResponse
        {
            AccessToken = "accessToken",
            ExpiresIn = 3600,
            IdToken = "idToken",
            RefreshToken = "refreshToken"
        };

        _mockApiClient
            .Setup(m => m.RefreshToken("validRefreshToken"))
            .ReturnsAsync(mockTokenResponse);

        var pastTime = DateTime.UtcNow.AddMinutes(-5);
        var pastExpiresAt = new DateTimeOffset(pastTime).ToUnixTimeMilliseconds();

        var beforeCall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var result = await _wristbandAuthService.RefreshTokenIfExpired("validRefreshToken", pastExpiresAt);
        var afterCall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        Assert.NotNull(result);

        // Verify ExpiresAt is calculated correctly (should be close to now + 3540 seconds in milliseconds)
        var expectedMinExpiresAt = beforeCall + (3540 * 1000);
        var expectedMaxExpiresAt = afterCall + (3540 * 1000);

        Assert.True(result.ExpiresAt >= expectedMinExpiresAt, $"ExpiresAt {result.ExpiresAt} should be >= {expectedMinExpiresAt}");
        Assert.True(result.ExpiresAt <= expectedMaxExpiresAt, $"ExpiresAt {result.ExpiresAt} should be <= {expectedMaxExpiresAt}");

        // Verify ExpiresIn accounts for buffer
        Assert.Equal(3540, result.ExpiresIn); // 3600 - 60 buffer
    }

    [Fact]
    public async Task RefreshTokenIfExpired_WithCustomTokenExpirationBuffer()
    {
        // Test with a custom token expiration buffer
        var customConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            DangerouslyDisableSecureCookies = false,
            LoginStateSecret = new string('a', 32),
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback",
            WristbandApplicationVanityDomain = "example.com",
            IsApplicationCustomDomainActive = false,
            TokenExpirationBuffer = 120 // 2 minutes buffer instead of default 60
        };

        var customService = new WristbandAuthService(customConfig);

        // Inject mock API client
        var fieldInfo = typeof(WristbandAuthService).GetField("mWristbandApiClient", BindingFlags.NonPublic | BindingFlags.Instance);
        fieldInfo?.SetValue(customService, _mockApiClient.Object);

        var mockTokenResponse = new TokenResponse
        {
            AccessToken = "accessToken",
            ExpiresIn = 3600,
            IdToken = "idToken",
            RefreshToken = "refreshToken"
        };

        _mockApiClient
            .Setup(m => m.RefreshToken("validRefreshToken"))
            .ReturnsAsync(mockTokenResponse);

        var pastTime = DateTime.UtcNow.AddMinutes(-5);
        var pastExpiresAt = new DateTimeOffset(pastTime).ToUnixTimeMilliseconds();

        var result = await customService.RefreshTokenIfExpired("validRefreshToken", pastExpiresAt);

        Assert.NotNull(result);
        Assert.Equal(3480, result.ExpiresIn); // 3600 - 120 buffer
    }
}
