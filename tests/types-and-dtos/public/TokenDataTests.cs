namespace Wristband.AspNet.Auth.Tests
{
    public class TokenDataTests
    {
        [Fact]
        public void Constructor_ShouldInitializeProperties_WhenValidArgumentsProvided()
        {
            // Arrange
            var accessToken = "testAccessToken";
            var expiresIn = 3600;
            var idToken = "testIdToken";
            var refreshToken = "testRefreshToken";

            // Act
            var tokenData = new TokenData(accessToken, expiresIn, idToken, refreshToken);

            // Assert
            Assert.Equal(accessToken, tokenData.AccessToken);
            Assert.Equal(expiresIn, tokenData.ExpiresIn);
            Assert.Equal(idToken, tokenData.IdToken);
            Assert.Equal(refreshToken, tokenData.RefreshToken);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_ShouldThrowException_WhenAccessTokenIsInvalid(string invalidAccessToken)
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new TokenData(invalidAccessToken, 3600, "validIdToken", "validRefreshToken"));

            Assert.Equal("[AccessToken] cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void Constructor_ShouldThrowException_WhenExpiresInIsNegative()
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new TokenData("validAccessToken", -1, "validIdToken", "validRefreshToken"));

            Assert.Equal("[ExpiresIn] must be a non-negative integer.", exception.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_ShouldThrowException_WhenIdTokenIsInvalid(string invalidIdToken)
        {
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new TokenData("validAccessToken", 3600, invalidIdToken, "validRefreshToken"));

            Assert.Equal("[IdToken] cannot be null or empty.", exception.Message);
        }
    }
}
