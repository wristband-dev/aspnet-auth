namespace Wristband.AspNet.Auth.Tests
{
    public class CallbackDataTests
    {
        [Fact]
        public void Constructor_NullUserinfo_ThrowsInvalidOperationException()
        {
            Assert.Throws<InvalidOperationException>(() => new CallbackData(
                accessToken: "token",
                expiresIn: 3600,
                idToken: "id_token",
                refreshToken: "refresh_token",
                userinfo: null!,
                tenantDomainName: "example.com",
                tenantCustomDomain: "custom.example.com",
                customState: null,
                returnUrl: "/dashboard"
            ));
        }

        [Fact]
        public void Constructor_NullOrEmptyTenantDomainName_ThrowsInvalidOperationException()
        {
            Assert.Throws<InvalidOperationException>(() => new CallbackData(
                accessToken: "token",
                expiresIn: 3600,
                idToken: "id_token",
                refreshToken: "refresh_token",
                userinfo: new UserInfo("{}"),
                tenantDomainName: null!,
                tenantCustomDomain: "custom.example.com",
                customState: null,
                returnUrl: "/dashboard"
            ));

            Assert.Throws<InvalidOperationException>(() => new CallbackData(
                accessToken: "token",
                expiresIn: 3600,
                idToken: "id_token",
                refreshToken: "refresh_token",
                userinfo: new UserInfo("{}"),
                tenantDomainName: "",
                tenantCustomDomain: "custom.example.com",
                customState: null,
                returnUrl: "/dashboard"
            ));
        }

        [Fact]
        public void Constructor_ValidParameters_CreatesInstanceSuccessfully()
        {
            var userinfo = new UserInfo("{\"name\":\"John\"}");
            var customState = new Dictionary<string, object> { { "key", "value" } };

            var callbackData = new CallbackData(
                accessToken: "token",
                expiresIn: 3600,
                idToken: "id_token",
                refreshToken: "refresh_token",
                userinfo: userinfo,
                tenantDomainName: "example.com",
                tenantCustomDomain: "custom.example.com",
                customState: customState,
                returnUrl: "/dashboard"
            );

            Assert.Equal("token", callbackData.AccessToken);
            Assert.Equal(3600, callbackData.ExpiresIn);
            Assert.Equal("id_token", callbackData.IdToken);
            Assert.Equal("refresh_token", callbackData.RefreshToken);
            Assert.Equal(userinfo, callbackData.Userinfo);
            Assert.Equal("example.com", callbackData.TenantDomainName);
            Assert.Equal("custom.example.com", callbackData.TenantCustomDomain);
            Assert.Equal(customState, callbackData.CustomState);
            Assert.Equal("/dashboard", callbackData.ReturnUrl);
        }

        [Fact]
        public void Constructor_NullOptionalParameters_SetsDefaults()
        {
            var callbackData = new CallbackData(
                accessToken: "token",
                expiresIn: 3600,
                idToken: "id_token",
                refreshToken: "refresh_token",
                userinfo: new UserInfo("{}"),
                tenantDomainName: "example.com",
                tenantCustomDomain: null,
                customState: null,
                returnUrl: null
            );

            Assert.Null(callbackData.TenantCustomDomain);
            Assert.Null(callbackData.CustomState);
            Assert.Null(callbackData.ReturnUrl);
        }

        [Fact]
        public void Empty_Instance_HasExpectedDefaultValues()
        {
            var empty = CallbackData.Empty;

            Assert.Equal("empty", empty.AccessToken);
            Assert.Equal(0, empty.ExpiresIn);
            Assert.Equal("empty", empty.IdToken);
            Assert.Null(empty.RefreshToken);
            Assert.Equal(UserInfo.Empty, empty.Userinfo);
            Assert.Equal("empty", empty.TenantDomainName);
            Assert.Null(empty.TenantCustomDomain);
            Assert.Null(empty.CustomState);
            Assert.Null(empty.ReturnUrl);
        }
    }
}
