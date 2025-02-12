namespace Wristband.AspNet.Auth.Tests
{
    public class LoginStateTests
    {
        [Fact]
        public void Constructor_WithValidParameters_ShouldInitializeProperties()
        {
            string state = "validState";
            string codeVerifier = "validCodeVerifier";
            string redirectUri = "https://example.com/callback";
            string returnUrl = "https://example.com/return";
            var customState = new Dictionary<string, object>
            {
                { "key1", "value1" },
                { "key2", 123 }
            };

            var loginState = new LoginState(state, codeVerifier, redirectUri, returnUrl, customState);

            Assert.Equal(state, loginState.State);
            Assert.Equal(codeVerifier, loginState.CodeVerifier);
            Assert.Equal(redirectUri, loginState.RedirectUri);
            Assert.Equal(returnUrl, loginState.ReturnUrl);
            Assert.Equal(customState, loginState.CustomState);
        }

        [Fact]
        public void Constructor_WithNullReturnUrl_ShouldAllowNull()
        {
            string state = "validState";
            string codeVerifier = "validCodeVerifier";
            string redirectUri = "https://example.com/callback";
            Dictionary<string, object>? customState = null;

            var loginState = new LoginState(state, codeVerifier, redirectUri, null!, customState);

            Assert.Equal(state, loginState.State);
            Assert.Equal(codeVerifier, loginState.CodeVerifier);
            Assert.Equal(redirectUri, loginState.RedirectUri);
            Assert.Null(loginState.ReturnUrl);
            Assert.Null(loginState.CustomState);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_WithInvalidState_ShouldThrowException(string? invalidState)
        {
            string codeVerifier = "validCodeVerifier";
            string redirectUri = "https://example.com/callback";
            string returnUrl = "https://example.com/return";
            var customState = new Dictionary<string, object>();

            var exception = Assert.Throws<InvalidOperationException>(() =>
                new LoginState(invalidState!, codeVerifier, redirectUri, returnUrl, customState));

            Assert.Equal("[State] cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_WithInvalidCodeVerifier_ShouldThrowException(string? invalidCodeVerifier)
        {
            string state = "validState";
            string redirectUri = "https://example.com/callback";
            string returnUrl = "https://example.com/return";
            var customState = new Dictionary<string, object>();

            var exception = Assert.Throws<InvalidOperationException>(() =>
                new LoginState(state, invalidCodeVerifier!, redirectUri, returnUrl, customState));

            Assert.Equal("[CodeVerifier] cannot be null or empty.", exception.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_WithInvalidRedirectUri_ShouldThrowException(string? invalidRedirectUri)
        {
            string state = "validState";
            string codeVerifier = "validCodeVerifier";
            string returnUrl = "https://example.com/return";
            var customState = new Dictionary<string, object>();

            var exception = Assert.Throws<InvalidOperationException>(() =>
                new LoginState(state, codeVerifier, invalidRedirectUri!, returnUrl, customState));

            Assert.Equal("[RedirectUri] cannot be null or empty.", exception.Message);
        }
    }
}
