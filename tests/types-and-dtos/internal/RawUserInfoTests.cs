namespace Wristband.AspNet.Auth.Tests
{
    public class RawUserInfoTests
    {
        [Fact]
        public void Constructor_NullOrEmptyJson_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => new RawUserInfo(null!));
            Assert.Throws<ArgumentException>(() => new RawUserInfo(""));
            Assert.Throws<ArgumentException>(() => new RawUserInfo("   "));
        }

        [Fact]
        public void Constructor_InvalidJson_ThrowsInvalidOperationException()
        {
            Assert.Throws<InvalidOperationException>(() => new RawUserInfo("invalid_json"));
            Assert.Throws<InvalidOperationException>(() => new RawUserInfo("{missing_colon}"));
        }

        [Fact]
        public void Constructor_ValidJson_ParsesSuccessfully()
        {
            string json = "{\"name\":\"John Doe\",\"age\":30}";
            var userInfo = new RawUserInfo(json);
            Assert.True(userInfo.TryGetValue("name", out var name));
            Assert.Equal("John Doe", name.GetString());
            Assert.True(userInfo.TryGetValue("age", out var age));
            Assert.Equal(30, age.GetInt32());
        }

        [Fact]
        public void GetValue_ExistingKey_ReturnsValue()
        {
            string json = "{\"key\":\"value\"}";
            var userInfo = new RawUserInfo(json);
            var result = userInfo.GetValue("key");
            Assert.Equal("value", result.GetString());
        }

        [Fact]
        public void GetValue_MissingKey_ThrowsKeyNotFoundException()
        {
            var userInfo = new RawUserInfo("{\"existingKey\":\"data\"}");
            Assert.Throws<KeyNotFoundException>(() => userInfo.GetValue("missingKey"));
        }

        [Fact]
        public void TryGetValue_ExistingKey_ReturnsTrueAndValue()
        {
            var userInfo = new RawUserInfo("{\"key\":\"value\"}");
            bool exists = userInfo.TryGetValue("key", out var value);
            Assert.True(exists);
            Assert.Equal("value", value.GetString());
        }

        [Fact]
        public void TryGetValue_MissingKey_ReturnsFalse()
        {
            var userInfo = new RawUserInfo("{\"existingKey\":\"data\"}");
            bool exists = userInfo.TryGetValue("missingKey", out var value);
            Assert.False(exists);
            Assert.Equal(default, value); // JsonElement default value is an empty element
        }
    }
}
