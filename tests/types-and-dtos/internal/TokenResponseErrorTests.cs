using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests
{
    public class TokenResponseErrorTests
    {
        [Fact]
        public void Constructor_ShouldInitializeWithDefaultValues()
        {
            var errorResponse = new TokenResponseError();

            Assert.NotNull(errorResponse);
            Assert.Equal(string.Empty, errorResponse.Error);
            Assert.Equal(string.Empty, errorResponse.ErrorDescription);
        }

        [Fact]
        public void Properties_ShouldAllowModification()
        {
            var errorResponse = new TokenResponseError();
            errorResponse.Error = "invalid_request";
            errorResponse.ErrorDescription = "The request is missing a required parameter.";

            Assert.Equal("invalid_request", errorResponse.Error);
            Assert.Equal("The request is missing a required parameter.", errorResponse.ErrorDescription);
        }

        [Fact]
        public void Should_SerializeCorrectly()
        {
            var errorResponse = new TokenResponseError
            {
                Error = "unauthorized_client",
                ErrorDescription = "The client is not authorized to request an access token."
            };

            string json = JsonSerializer.Serialize(errorResponse);

            Assert.Contains("\"error\":\"unauthorized_client\"", json);
            Assert.Contains("\"error_description\":\"The client is not authorized to request an access token.\"", json);
        }

        [Fact]
        public void Should_DeserializeCorrectly()
        {
            string json = "{\"error\":\"access_denied\",\"error_description\":\"The user denied the request.\"}";

            var errorResponse = JsonSerializer.Deserialize<TokenResponseError>(json);

            Assert.NotNull(errorResponse);
            Assert.Equal("access_denied", errorResponse.Error);
            Assert.Equal("The user denied the request.", errorResponse.ErrorDescription);
        }

        [Fact]
        public void Should_HandleMissingErrorDescription_WhenDeserializing()
        {
            string json = "{\"error\":\"invalid_token\"}";

            var errorResponse = JsonSerializer.Deserialize<TokenResponseError>(json);

            Assert.NotNull(errorResponse);
            Assert.Equal("invalid_token", errorResponse.Error);
            Assert.Equal(string.Empty, errorResponse.ErrorDescription);
        }

        [Fact]
        public void Should_HandleEmptyJson_WhenDeserializing()
        {
            string json = "{}";

            var errorResponse = JsonSerializer.Deserialize<TokenResponseError>(json);

            Assert.NotNull(errorResponse);
            Assert.Equal(string.Empty, errorResponse.Error);
            Assert.Equal(string.Empty, errorResponse.ErrorDescription);
        }
    }
}
