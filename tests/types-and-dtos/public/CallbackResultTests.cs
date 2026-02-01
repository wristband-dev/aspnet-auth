namespace Wristband.AspNet.Auth.Tests;

public class CallbackResultTests
{
    [Fact]
    public void Constructor_CompletedResultWithNullCallbackData_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(
            () => new CallbackResult(CallbackResultType.Completed, null, "https://example.com")
        );

        Assert.Equal("callbackData", exception.ParamName);
    }

    [Fact]
    public void Constructor_RedirectRequiredWithNullRedirectUrl_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(
            () => new CallbackResult(CallbackResultType.RedirectRequired, CallbackData.Empty, null, CallbackFailureReason.LoginRequired)
        );

        Assert.Equal("redirectUrl", exception.ParamName);
    }

    [Fact]
    public void Constructor_RedirectRequiredWithEmptyRedirectUrl_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(
            () => new CallbackResult(CallbackResultType.RedirectRequired, CallbackData.Empty, "", CallbackFailureReason.LoginRequired)
        );

        Assert.Equal("redirectUrl", exception.ParamName);
    }

    [Fact]
    public void Constructor_RedirectRequiredWithNullReason_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(
            () => new CallbackResult(CallbackResultType.RedirectRequired, CallbackData.Empty, "https://example.com", null)
        );

        Assert.Equal("redirectUrl", exception.ParamName);
    }

    [Fact]
    public void Constructor_ValidCompletedResult_SetsPropertiesCorrectly()
    {
        var callbackData = CallbackData.Empty;

        var result = new CallbackResult(CallbackResultType.Completed, callbackData, "https://example.com");

        Assert.Equal(CallbackResultType.Completed, result.Type);
        Assert.Same(callbackData, result.CallbackData);
        Assert.Equal("https://example.com", result.RedirectUrl);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Constructor_ValidRedirectRequiredResult_SetsPropertiesCorrectly()
    {
        var callbackData = CallbackData.Empty;
        var redirectUrl = "https://redirect.example.com";

        var result = new CallbackResult(CallbackResultType.RedirectRequired, callbackData, redirectUrl, CallbackFailureReason.LoginRequired);

        Assert.Equal(CallbackResultType.RedirectRequired, result.Type);
        Assert.Same(callbackData, result.CallbackData);
        Assert.Equal(redirectUrl, result.RedirectUrl);
        Assert.Equal(CallbackFailureReason.LoginRequired, result.Reason);
    }

    [Fact]
    public void Constructor_RedirectRequiredWithMissingLoginState_SetsReasonCorrectly()
    {
        var result = new CallbackResult(CallbackResultType.RedirectRequired, CallbackData.Empty, "https://example.com", CallbackFailureReason.MissingLoginState);

        Assert.Equal(CallbackFailureReason.MissingLoginState, result.Reason);
    }

    [Fact]
    public void Constructor_RedirectRequiredWithInvalidLoginState_SetsReasonCorrectly()
    {
        var result = new CallbackResult(CallbackResultType.RedirectRequired, CallbackData.Empty, "https://example.com", CallbackFailureReason.InvalidLoginState);

        Assert.Equal(CallbackFailureReason.InvalidLoginState, result.Reason);
    }

    [Fact]
    public void Constructor_RedirectRequiredWithInvalidGrant_SetsReasonCorrectly()
    {
        var result = new CallbackResult(CallbackResultType.RedirectRequired, CallbackData.Empty, "https://example.com", CallbackFailureReason.InvalidGrant);

        Assert.Equal(CallbackFailureReason.InvalidGrant, result.Reason);
    }

    [Fact]
    public void Constructor_CompletedResult_ReasonIsNull()
    {
        var result = new CallbackResult(CallbackResultType.Completed, CallbackData.Empty, null);

        Assert.Null(result.Reason);
    }

    [Fact]
    public void Constructor_CompletedResult_NullRedirectUrlDefaultsToEmptyString()
    {
        var result = new CallbackResult(CallbackResultType.Completed, CallbackData.Empty, null);

        Assert.Equal(string.Empty, result.RedirectUrl);
    }
}
