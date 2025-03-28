namespace Wristband.AspNet.Auth.Tests
{
    public class LoginConfigTests
    {
        [Fact]
        public void DefaultConstructor_ShouldInitializePropertiesAsNull()
        {
            var config = new LoginConfig();

            Assert.Null(config.CustomState);
            Assert.Null(config.DefaultTenantCustomDomain);
            Assert.Null(config.DefaultTenantDomainName);
        }

        [Fact]
        public void Constructor_WithValidValues_ShouldSetProperties()
        {
            var customState = new Dictionary<string, object> { { "key", "value" } };
            var defaultTenantCustomDomain = "custom.example.com";
            var defaultTenantDomainName = "example.com";

            var config = new LoginConfig(customState, defaultTenantCustomDomain, defaultTenantDomainName);

            Assert.NotNull(config.CustomState);
            Assert.True(config.CustomState.ContainsKey("key"));
            Assert.Equal("value", config.CustomState["key"]);
            Assert.Equal(defaultTenantCustomDomain, config.DefaultTenantCustomDomain);
            Assert.Equal(defaultTenantDomainName, config.DefaultTenantDomainName);
        }

        [Fact]
        public void Constructor_WithNullValues_ShouldSetPropertiesToNull()
        {
            var config = new LoginConfig(null, null, null);

            Assert.Null(config.CustomState);
            Assert.Null(config.DefaultTenantCustomDomain);
            Assert.Null(config.DefaultTenantDomainName);
        }

        [Fact]
        public void Properties_ShouldBeSettableAfterConstruction()
        {
            var config = new LoginConfig();

            var newCustomState = new Dictionary<string, object> { { "foo", 42 } };
            config.CustomState = newCustomState;
            config.DefaultTenantCustomDomain = "updated.example.com";
            config.DefaultTenantDomainName = "updated.com";

            Assert.NotNull(config.CustomState);
            Assert.True(config.CustomState.ContainsKey("foo"));
            Assert.Equal(42, config.CustomState["foo"]);
            Assert.Equal("updated.example.com", config.DefaultTenantCustomDomain);
            Assert.Equal("updated.com", config.DefaultTenantDomainName);
        }
    }
}
