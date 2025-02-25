using System.Reflection;

using Moq;

namespace Wristband.AspNet.Auth.Tests
{
    public class RefreshTokenIfExpiredTests
    {
        private readonly Mock<IWristbandNetworking> _mockNetworking = new Mock<IWristbandNetworking>();

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
                WristbandApplicationDomain = "example.com",
                RootDomain = "example.com",
                UseCustomDomains = false,
                UseTenantSubdomains = false
            };

            _wristbandAuthService = new WristbandAuthService(_authConfig);

            // Use reflection to inject the mock networking object into the service
            var fieldInfo = typeof(WristbandAuthService).GetField("mWristbandNetworking", BindingFlags.NonPublic | BindingFlags.Instance);
            if (fieldInfo != null && _mockNetworking != null)
            {
                fieldInfo.SetValue(_wristbandAuthService, _mockNetworking.Object);
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
            var expectedTokenData = new TokenData("newAccessToken", 3600, "newIdToken", "newRefreshToken");

            _mockNetworking
                .Setup(m => m.RefreshToken("validRefreshToken"))
                .ReturnsAsync(expectedTokenData);

            var dateTime = DateTime.UtcNow.AddMinutes(-5);
            var msSinceEpoch = new DateTimeOffset(dateTime).ToUnixTimeMilliseconds();

            var result = await _wristbandAuthService.RefreshTokenIfExpired("validRefreshToken", msSinceEpoch);

            Assert.NotNull(result);
            Assert.Equal("newAccessToken", result.AccessToken);
            Assert.Equal(3600, result.ExpiresIn);
            Assert.Equal("newIdToken", result.IdToken);
            Assert.Equal("newRefreshToken", result.RefreshToken);
        }

        [Fact]
        public async Task RefreshTokenIfExpired_InvalidRefreshToken_ThrowsWristbandError()
        {
            _mockNetworking
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

        [Fact]
        public async Task RefreshTokenIfExpired_ServerError_RetryAndSucceed()
        {
            // Setup to fail with 500 once, then succeed
            _mockNetworking
                .SetupSequence(m => m.RefreshToken("validRefreshToken"))
                .ThrowsAsync(new WristbandError("unexpected_error", "Unexpected Error"))
                .ReturnsAsync(new TokenData("newAccessToken", 3600, "newIdToken", "newRefreshToken"));

            var dateTime = DateTime.UtcNow.AddMinutes(-5);
            var msSinceEpoch = new DateTimeOffset(dateTime).ToUnixTimeMilliseconds();

            var result = await _wristbandAuthService.RefreshTokenIfExpired("validRefreshToken", msSinceEpoch);

            Assert.NotNull(result);
            Assert.Equal("newAccessToken", result.AccessToken);
            Assert.Equal(3600, result.ExpiresIn);
            Assert.Equal("newIdToken", result.IdToken);
            Assert.Equal("newRefreshToken", result.RefreshToken);
        }

        [Fact]
        public async Task RefreshTokenIfExpired_ServerError_ExhaustsRetries()
        {
            _mockNetworking
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
    }
}
