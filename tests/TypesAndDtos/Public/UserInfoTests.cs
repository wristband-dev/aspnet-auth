namespace Wristband.AspNet.Auth.Tests
{
    public class UserInfoTests
    {
        [Fact]
        public void Constructor_NullOrEmptyJson_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() => new UserInfo(null!));
            Assert.Throws<ArgumentException>(() => new UserInfo(""));
            Assert.Throws<ArgumentException>(() => new UserInfo("   "));
        }

        [Fact]
        public void Constructor_InvalidJson_ThrowsInvalidOperationException()
        {
            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => new UserInfo("invalid_json"));
            Assert.Throws<InvalidOperationException>(() => new UserInfo("{missing_colon}"));
        }

        [Fact]
        public void Constructor_ValidJson_ParsesSuccessfully()
        {
            // Arrange
            string json = "{\"name\":\"John Doe\",\"age\":30}";

            // Act
            var userInfo = new UserInfo(json);

            // Assert
            Assert.True(userInfo.TryGetValue("name", out var name));
            Assert.Equal("John Doe", name.GetString());

            Assert.True(userInfo.TryGetValue("age", out var age));
            Assert.Equal(30, age.GetInt32());
        }

        [Fact]
        public void GetValue_ExistingKey_ReturnsValue()
        {
            // Arrange
            string json = "{\"key\":\"value\"}";
            var userInfo = new UserInfo(json);

            // Act
            var result = userInfo.GetValue("key");

            // Assert
            Assert.Equal("value", result.GetString());
        }

        [Fact]
        public void GetValue_MissingKey_ThrowsKeyNotFoundException()
        {
            // Arrange
            var userInfo = new UserInfo("{\"existingKey\":\"data\"}");

            // Act & Assert
            Assert.Throws<KeyNotFoundException>(() => userInfo.GetValue("missingKey"));
        }

        [Fact]
        public void TryGetValue_ExistingKey_ReturnsTrueAndValue()
        {
            // Arrange
            var userInfo = new UserInfo("{\"key\":\"value\"}");

            // Act
            bool exists = userInfo.TryGetValue("key", out var value);

            // Assert
            Assert.True(exists);
            Assert.Equal("value", value.GetString());
        }

        [Fact]
        public void TryGetValue_MissingKey_ReturnsFalse()
        {
            // Arrange
            var userInfo = new UserInfo("{\"existingKey\":\"data\"}");

            // Act
            bool exists = userInfo.TryGetValue("missingKey", out var value);

            // Assert
            Assert.False(exists);
            Assert.Equal(default, value); // JsonElement default value is an empty element
        }

        [Fact]
        public void StaticEmptyInstance_HasValidEmptyJson()
        {
            // Arrange
            var emptyUserInfo = UserInfo.Empty;

            // Act
            bool exists = emptyUserInfo.TryGetValue("anyKey", out var value);

            // Assert
            Assert.False(exists);
            Assert.Equal(default, value);
        }
    }
}
