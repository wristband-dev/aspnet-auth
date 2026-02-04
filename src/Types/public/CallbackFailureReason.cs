namespace Wristband.AspNet.Auth;

/// <summary>
/// Reason why callback processing failed and requires a redirect to retry authentication.
/// </summary>
public enum CallbackFailureReason
{
    /// <summary>
    /// Login state cookie was not found (cookie expired or bookmarked callback URL).
    /// </summary>
    MissingLoginState,

    /// <summary>
    /// Login state validation failed (possible CSRF attack or cookie tampering).
    /// </summary>
    InvalidLoginState,

    /// <summary>
    /// Wristband returned a login_required error (session expired or max_age elapsed).
    /// </summary>
    LoginRequired,

    /// <summary>
    /// Authorization code was invalid, expired, or already used.
    /// </summary>
    InvalidGrant,
}
