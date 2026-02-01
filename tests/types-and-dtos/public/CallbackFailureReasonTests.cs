namespace Wristband.AspNet.Auth.Tests;

public class CallbackFailureReasonTests
{
    [Fact]
    public void Enum_HasExpectedValues()
    {
        Assert.Equal(0, (int)CallbackFailureReason.MissingLoginState);
        Assert.Equal(1, (int)CallbackFailureReason.InvalidLoginState);
        Assert.Equal(2, (int)CallbackFailureReason.LoginRequired);
        Assert.Equal(3, (int)CallbackFailureReason.InvalidGrant);
    }

    [Fact]
    public void Enum_CanBeAssigned()
    {
        CallbackFailureReason reason = CallbackFailureReason.MissingLoginState;
        Assert.Equal(CallbackFailureReason.MissingLoginState, reason);

        reason = CallbackFailureReason.InvalidLoginState;
        Assert.Equal(CallbackFailureReason.InvalidLoginState, reason);

        reason = CallbackFailureReason.LoginRequired;
        Assert.Equal(CallbackFailureReason.LoginRequired, reason);

        reason = CallbackFailureReason.InvalidGrant;
        Assert.Equal(CallbackFailureReason.InvalidGrant, reason);
    }

    [Fact]
    public void Enum_CanBeUsedInSwitch()
    {
        var reason = CallbackFailureReason.LoginRequired;

        var result = reason switch
        {
            CallbackFailureReason.MissingLoginState => "missing",
            CallbackFailureReason.InvalidLoginState => "invalid",
            CallbackFailureReason.LoginRequired => "login_required",
            CallbackFailureReason.InvalidGrant => "invalid_grant",
            _ => "unknown"
        };

        Assert.Equal("login_required", result);
    }

    [Fact]
    public void Enum_CanBeCompared()
    {
#pragma warning disable CS1718 // Comparison made to same variable
        Assert.True(CallbackFailureReason.MissingLoginState == CallbackFailureReason.MissingLoginState);
#pragma warning restore CS1718 // Comparison made to same variable
        Assert.False(CallbackFailureReason.MissingLoginState == CallbackFailureReason.InvalidGrant);
        Assert.True(CallbackFailureReason.LoginRequired != CallbackFailureReason.InvalidLoginState);
    }

    [Fact]
    public void Enum_ToStringReturnsName()
    {
        Assert.Equal("MissingLoginState", CallbackFailureReason.MissingLoginState.ToString());
        Assert.Equal("InvalidLoginState", CallbackFailureReason.InvalidLoginState.ToString());
        Assert.Equal("LoginRequired", CallbackFailureReason.LoginRequired.ToString());
        Assert.Equal("InvalidGrant", CallbackFailureReason.InvalidGrant.ToString());
    }

    [Fact]
    public void Enum_AllValuesDefined()
    {
        var values = Enum.GetValues<CallbackFailureReason>();

        Assert.Equal(4, values.Length);
        Assert.Contains(CallbackFailureReason.MissingLoginState, values);
        Assert.Contains(CallbackFailureReason.InvalidLoginState, values);
        Assert.Contains(CallbackFailureReason.LoginRequired, values);
        Assert.Contains(CallbackFailureReason.InvalidGrant, values);
    }
}
