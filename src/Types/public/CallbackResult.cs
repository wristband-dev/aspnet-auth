namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the result of the callback execution after authentication.
/// It can include the set of callback data necessary for creating an authenticated session in the event a redirect is not required.
/// </summary>
public class CallbackResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CallbackResult"/> class.
    /// </summary>
    /// <param name="type">The type of result of the callback execution.</param>
    /// <param name="callbackData">The callback data received after authentication (required only for Completed result).</param>
    /// <param name="redirectUrl">The URL to redirect to (required only for RedirectRequired result).</param>
    /// <param name="reason">Optional reason why a redirect is required (only for RedirectRequired result).</param>
    /// <exception cref="ArgumentNullException">Thrown when callback data is null for the Completed result or redirect URL is null for the RedirectRequired result.</exception>
    public CallbackResult(
        CallbackResultType type,
        CallbackData? callbackData,
        string? redirectUrl,
        CallbackFailureReason? reason = null)
    {
        if (type == CallbackResultType.Completed && callbackData == null)
        {
            throw new ArgumentNullException(nameof(callbackData), "CallbackData cannot be null for Completed result.");
        }

        if (type == CallbackResultType.RedirectRequired)
        {
            if (string.IsNullOrEmpty(redirectUrl))
            {
                throw new ArgumentNullException(nameof(redirectUrl), "RedirectUrl cannot be null for RedirectRequired result.");
            }

            if (reason == null)
            {
                throw new ArgumentNullException(nameof(redirectUrl), "Reason cannot be null for RedirectRequired result.");
            }
        }

        Type = type;
        CallbackData = callbackData ?? CallbackData.Empty;
        RedirectUrl = redirectUrl ?? string.Empty;
        Reason = reason;
    }

    /// <summary>
    /// Gets the callback data received after authentication (Completed result only).
    /// </summary>
    public CallbackData CallbackData { get; }

    /// <summary>
    /// Gets the URL to redirect to (RedirectRequired result only).
    /// </summary>
    public string RedirectUrl { get; }

    /// <summary>
    /// Gets the type of result of the callback execution.
    /// </summary>
    public CallbackResultType Type { get; }

    /// <summary>
    /// Gets the specific reason why a redirect is required (RedirectRequired result only).
    /// </summary>
    public CallbackFailureReason? Reason { get; }
}
