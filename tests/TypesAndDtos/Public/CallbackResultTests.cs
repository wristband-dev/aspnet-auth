using System;
using System.Collections.Generic;

using Xunit;

namespace Wristband.AspNet.Auth.Tests
{
    public class CallbackResultTests
    {
        [Fact]
        public void Constructor_CompletedResultWithNullCallbackData_ThrowsArgumentNullException()
        {
            var exception = Assert.Throws<ArgumentNullException>(
                () => new CallbackResult(CallbackResultType.COMPLETED, null, "https://example.com")
            );

            Assert.Equal("callbackData", exception.ParamName);
        }

        [Fact]
        public void Constructor_RedirectRequiredWithNullRedirectUrl_ThrowsArgumentNullException()
        {
            var exception = Assert.Throws<ArgumentNullException>(
                () => new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, CallbackData.Empty, null)
            );

            Assert.Equal("redirectUrl", exception.ParamName);
        }

        [Fact]
        public void Constructor_RedirectRequiredWithEmptyRedirectUrl_ThrowsArgumentNullException()
        {
            var exception = Assert.Throws<ArgumentNullException>(
                () => new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, CallbackData.Empty, "")
            );

            Assert.Equal("redirectUrl", exception.ParamName);
        }

        [Fact]
        public void Constructor_ValidCompletedResult_SetsPropertiesCorrectly()
        {
            var callbackData = CallbackData.Empty;

            var result = new CallbackResult(CallbackResultType.COMPLETED, callbackData, "https://example.com");

            Assert.Equal(CallbackResultType.COMPLETED, result.Result);
            Assert.Same(callbackData, result.CallbackData);
            Assert.Equal("https://example.com", result.RedirectUrl);
        }

        [Fact]
        public void Constructor_ValidRedirectRequiredResult_SetsPropertiesCorrectly()
        {
            var callbackData = CallbackData.Empty;
            var redirectUrl = "https://redirect.example.com";

            var result = new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, callbackData, redirectUrl);

            Assert.Equal(CallbackResultType.REDIRECT_REQUIRED, result.Result);
            Assert.Same(callbackData, result.CallbackData);
            Assert.Equal(redirectUrl, result.RedirectUrl);
        }

        [Fact]
        public void Constructor_NullCallbackDataDefaultsToEmpty()
        {
            var result = new CallbackResult(CallbackResultType.REDIRECT_REQUIRED, null, "https://example.com");

            Assert.Equal(CallbackData.Empty, result.CallbackData);
        }

        [Fact]
        public void Constructor_NullRedirectUrlDefaultsToEmptyString()
        {
            var result = new CallbackResult(CallbackResultType.COMPLETED, CallbackData.Empty, null);

            Assert.Equal(string.Empty, result.RedirectUrl);
        }
    }
}
