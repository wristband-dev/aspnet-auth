namespace Wristband.AspNet.Auth.Tests
{
    public class InvalidGrantErrorTests
    {
        [Fact]
        public void Constructor_WithErrorDescription_SetsProperties()
        {
            // Act
            var error = new TestInvalidGrantError("Test error description");

            // Assert
            Assert.Equal("invalid_grant", error.Error);
            Assert.Equal("Test error description", error.ErrorDescription);
            Assert.Equal("invalid_grant", error.Message);
        }

        [Fact]
        public void Constructor_WithNullErrorDescription_SetsEmptyString()
        {
            // Act
            var error = new TestInvalidGrantError(null);

            // Assert
            Assert.Equal("invalid_grant", error.Error);
            Assert.Equal(string.Empty, error.ErrorDescription);
        }

        [Fact]
        public void Constructor_InheritsFromWristbandError()
        {
            // Act
            var error = new TestInvalidGrantError("Test description");

            // Assert
            Assert.IsAssignableFrom<WristbandError>(error);
        }

        [Fact]
        public void Constructor_SetsPredefinedErrorCode()
        {
            // Arrange & Act
            var error1 = new TestInvalidGrantError("Description 1");
            var error2 = new TestInvalidGrantError("Description 2");

            // Assert
            Assert.Equal("invalid_grant", error1.Error);
            Assert.Equal("invalid_grant", error2.Error);
        }

        [Fact]
        public void Exception_CanBeCaught()
        {
            // Arrange
            bool exceptionCaught = false;

            // Act
            try
            {
                ThrowInvalidGrantError();
            }
            catch (WristbandError error)
            {
                exceptionCaught = true;
                Assert.Equal("invalid_grant", error.Error);
            }

            // Assert
            Assert.True(exceptionCaught);
        }

        [Fact]
        public void Exception_CanBeCaughtSpecifically()
        {
            // Arrange
            bool specificExceptionCaught = false;

            // Act
            try
            {
                ThrowInvalidGrantError();
            }
            catch (TestInvalidGrantError error)
            {
                specificExceptionCaught = true;
                Assert.Equal("invalid_grant", error.Error);
            }

            // Assert
            Assert.True(specificExceptionCaught);
        }

        private void ThrowInvalidGrantError()
        {
            throw new TestInvalidGrantError("Test exception");
        }

        // We need a test wrapper class since InvalidGrantError is internal
        private class TestInvalidGrantError : InvalidGrantError
        {
            public TestInvalidGrantError(string? errorDescription)
                : base(errorDescription)
            {
            }
        }
    }
}
