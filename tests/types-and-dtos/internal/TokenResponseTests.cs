using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests
{
    public class TokenResponseTests
    {
        [Fact]
        public void Constructor_ShouldInitializeWithDefaultValues()
        {
            var tokenResponse = new TokenResponse();

            Assert.NotNull(tokenResponse);
            Assert.Equal(string.Empty, tokenResponse.AccessToken);
            Assert.Equal(0, tokenResponse.ExpiresIn);
            Assert.Equal(string.Empty, tokenResponse.IdToken);
            Assert.Null(tokenResponse.RefreshToken);
            Assert.Equal(string.Empty, tokenResponse.Scope);
            Assert.Equal(string.Empty, tokenResponse.TokenType);
        }

        [Fact]
        public void Properties_ShouldAllowModification()
        {
            var tokenResponse = new TokenResponse();

            tokenResponse.AccessToken = "access123";
            tokenResponse.ExpiresIn = 3600;
            tokenResponse.IdToken = "id123";
            tokenResponse.RefreshToken = "refresh123";
            tokenResponse.Scope = "openid profile";
            tokenResponse.TokenType = "Bearer";

            Assert.Equal("access123", tokenResponse.AccessToken);
            Assert.Equal(3600, tokenResponse.ExpiresIn);
            Assert.Equal("id123", tokenResponse.IdToken);
            Assert.Equal("refresh123", tokenResponse.RefreshToken);
            Assert.Equal("openid profile", tokenResponse.Scope);
            Assert.Equal("Bearer", tokenResponse.TokenType);
        }

        [Fact]
        public void Should_SerializeCorrectly()
        {
            var tokenResponse = new TokenResponse
            {
                AccessToken = "access123",
                ExpiresIn = 3600,
                IdToken = "id123",
                RefreshToken = "refresh123",
                Scope = "openid profile",
                TokenType = "Bearer"
            };

            string json = JsonSerializer.Serialize(tokenResponse);

            Assert.Contains("\"access_token\":\"access123\"", json);
            Assert.Contains("\"expires_in\":3600", json);
            Assert.Contains("\"id_token\":\"id123\"", json);
            Assert.Contains("\"refresh_token\":\"refresh123\"", json);
            Assert.Contains("\"scope\":\"openid profile\"", json);
            Assert.Contains("\"token_type\":\"Bearer\"", json);
        }

        [Fact]
        public void Should_DeserializeCorrectly()
        {
            string json = "{\"access_token\":\"access123\",\"expires_in\":3600,\"id_token\":\"id123\",\"refresh_token\":\"refresh123\",\"scope\":\"openid profile\",\"token_type\":\"Bearer\"}";

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);

            Assert.NotNull(tokenResponse);
            Assert.Equal("access123", tokenResponse.AccessToken);
            Assert.Equal(3600, tokenResponse.ExpiresIn);
            Assert.Equal("id123", tokenResponse.IdToken);
            Assert.Equal("refresh123", tokenResponse.RefreshToken);
            Assert.Equal("openid profile", tokenResponse.Scope);
            Assert.Equal("Bearer", tokenResponse.TokenType);
        }

        [Fact]
        public void Should_HandleMissingRefreshToken_WhenDeserializing()
        {
            string json = "{\"access_token\":\"access123\",\"expires_in\":3600,\"id_token\":\"id123\",\"scope\":\"openid profile\",\"token_type\":\"Bearer\"}";

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);

            Assert.NotNull(tokenResponse);
            Assert.Equal("access123", tokenResponse.AccessToken);
            Assert.Equal(3600, tokenResponse.ExpiresIn);
            Assert.Equal("id123", tokenResponse.IdToken);
            Assert.Null(tokenResponse.RefreshToken);
            Assert.Equal("openid profile", tokenResponse.Scope);
            Assert.Equal("Bearer", tokenResponse.TokenType);
        }

        [Fact]
        public void Should_HandleEmptyJson_WhenDeserializing()
        {
            string json = "{}";

            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);

            Assert.NotNull(tokenResponse);
            Assert.Equal(string.Empty, tokenResponse.AccessToken);
            Assert.Equal(0, tokenResponse.ExpiresIn);
            Assert.Equal(string.Empty, tokenResponse.IdToken);
            Assert.Null(tokenResponse.RefreshToken);
            Assert.Equal(string.Empty, tokenResponse.Scope);
            Assert.Equal(string.Empty, tokenResponse.TokenType);
        }
    }
}
