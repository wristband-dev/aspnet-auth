namespace Wristband.AspNet.Auth.Tests
{
    public class WristbandErrorTests
    {
        [Fact]
        public void Constructor_ShouldSetPropertiesCorrectly()
        {
            // Arrange
            string expectedError = "invalid_request";
            string expectedDescription = "The request was malformed.";

            // Act
            var exception = new WristbandError(expectedError, expectedDescription);

            // Assert
            Assert.Equal(expectedError, exception.Error);
            Assert.Equal(expectedDescription, exception.ErrorDescription);
            Assert.Equal(expectedError, exception.Message); // Exception message should match the error
        }

        [Fact]
        public void Constructor_ShouldSetErrorDescriptionToEmptyString_WhenNullProvided()
        {
            // Arrange
            string expectedError = "server_error";

            // Act
            var exception = new WristbandError(expectedError, null);

            // Assert
            Assert.Equal(expectedError, exception.Error);
            Assert.Equal(string.Empty, exception.ErrorDescription);
            Assert.Equal(expectedError, exception.Message);
        }

        [Fact]
        public void Exception_ShouldBeThrowableAndCatchable()
        {
            // Arrange
            string expectedError = "access_denied";
            string expectedDescription = "User denied access.";

            // Act & Assert
            try
            {
                throw new WristbandError(expectedError, expectedDescription);
            }
            catch (WristbandError ex)
            {
                Assert.Equal(expectedError, ex.Error);
                Assert.Equal(expectedDescription, ex.ErrorDescription);
                Assert.Equal(expectedError, ex.Message);
            }
        }
    }
}
