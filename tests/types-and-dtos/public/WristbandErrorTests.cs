namespace Wristband.AspNet.Auth.Tests
{
    public class WristbandErrorTests
    {
        [Fact]
        public void Constructor_ShouldSetPropertiesCorrectly()
        {
            string expectedError = "invalid_request";
            string expectedDescription = "The request was malformed.";
            var exception = new WristbandError(expectedError, expectedDescription);

            Assert.Equal(expectedError, exception.Error);
            Assert.Equal(expectedDescription, exception.ErrorDescription);
            Assert.Equal(expectedError, exception.Message); // Exception message should match the error
        }

        [Fact]
        public void Constructor_ShouldSetErrorDescriptionToEmptyString_WhenNullProvided()
        {
            string expectedError = "server_error";
            var exception = new WristbandError(expectedError, null);

            Assert.Equal(expectedError, exception.Error);
            Assert.Equal(string.Empty, exception.ErrorDescription);
            Assert.Equal(expectedError, exception.Message);
        }

        [Fact]
        public void Exception_ShouldBeThrowableAndCatchable()
        {
            string expectedError = "access_denied";
            string expectedDescription = "User denied access.";

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
