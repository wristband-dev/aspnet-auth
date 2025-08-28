namespace Wristband.AspNet.Auth.Tests
{
    public class TokenDataTests
    {
        [Fact]
        public void Constructor_ShouldInitializeProperties_WhenValidArgumentsProvided()
        {
            // Arrange
            var accessToken = "testAccessToken";
            var expiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds();
            var expiresIn = 3600;
            var idToken = "testIdToken";
            var refreshToken = "testRefreshToken";

            // Act
            var tokenData = new TokenData(accessToken, expiresAt, expiresIn, idToken, refreshToken);

            // Assert
            Assert.Equal(accessToken, tokenData.AccessToken);
            Assert.Equal(expiresAt, tokenData.ExpiresAt);
            Assert.Equal(expiresIn, tokenData.ExpiresIn);
            Assert.Equal(idToken, tokenData.IdToken);
            Assert.Equal(refreshToken, tokenData.RefreshToken);
        }

        [Fact]
        public void Constructor_ShouldInitializeProperties_WhenRefreshTokenIsNull()
        {
            // Arrange
            var accessToken = "testAccessToken";
            var expiresAt = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds();
            var expiresIn = 3600;
            var idToken = "testIdToken";

            // Act
            var tokenData = new TokenData(accessToken, expiresAt, expiresIn, idToken, null);

            // Assert
            Assert.Equal(accessToken, tokenData.AccessToken);
            Assert.Equal(expiresAt, tokenData.ExpiresAt);
            Assert.Equal(expiresIn, tokenData.ExpiresIn);
            Assert.Equal(idToken, tokenData.IdToken);
            Assert.Null(tokenData.RefreshToken);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_ShouldThrowException_WhenAccessTokenIsInvalid(string invalidAccessToken)
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new TokenData(invalidAccessToken, 1234567890000, 3600, "validIdToken", "validRefreshToken"));

            Assert.Equal("[AccessToken] cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenExpiresAtIsNegative()
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new TokenData("validAccessToken", -1, 3600, "validIdToken", "validRefreshToken"));

            Assert.Equal("[ExpiresAt] must be a non-negative integer.", exception.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenExpiresInIsNegative()
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new TokenData("validAccessToken", 1234567890000, -1, "validIdToken", "validRefreshToken"));

            Assert.Equal("[ExpiresIn] must be a non-negative integer.", exception.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_ShouldThrowException_WhenIdTokenIsInvalid(string invalidIdToken)
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new TokenData("validAccessToken", 1234567890000, 3600, invalidIdToken, "validRefreshToken"));

            Assert.Equal("[IdToken] cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void Constructor_ShouldAllowZeroExpiresAt()
        {
            // Act & Assert - should not throw
            var tokenData = new TokenData("validAccessToken", 0, 3600, "validIdToken", "validRefreshToken");

            Assert.Equal(0, tokenData.ExpiresAt);
        }

        [Fact]
        public void Constructor_ShouldAllowZeroExpiresIn()
        {
            // Act & Assert - should not throw
            var tokenData = new TokenData("validAccessToken", 1234567890000, 0, "validIdToken", "validRefreshToken");

            Assert.Equal(0, tokenData.ExpiresIn);
        }

        [Fact]
        public void Constructor_ShouldAllowLargeExpiresAtValue()
        {
            // Arrange - test with a large timestamp (year 2050)
            var largeExpiresAt = 2524608000000L; // January 1, 2050

            // Act & Assert - should not throw
            var tokenData = new TokenData("validAccessToken", largeExpiresAt, 3600, "validIdToken", "validRefreshToken");

            Assert.Equal(largeExpiresAt, tokenData.ExpiresAt);
        }
    }
}
