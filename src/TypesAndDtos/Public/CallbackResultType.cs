namespace Wristband.AspNet.Auth;

/// <summary>
/// Enum representing different possible results from the execution of the callback handler.
/// </summary>
public enum CallbackResultType
{
    /// <summary>
    /// Indicates that the callback is successfully completed and data is available for creating a session.
    /// </summary>
    COMPLETED,

    /// <summary>
    /// Indicates that a redirect is required, generally to a login route or page.
    /// </summary>
    REDIRECT_REQUIRED,
}
