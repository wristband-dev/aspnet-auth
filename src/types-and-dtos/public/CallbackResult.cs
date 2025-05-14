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
    /// <param name="callbackData">The callback data received after authentication (required only for COMPLETED result).</param>
    /// <param name="redirectUrl">The URL to redirect to (required only for REDIRECT_REQUIRED result).</param>
    /// <exception cref="ArgumentNullException">Thrown when callback data is null for the COMPLETED result or redirect URL is null for the REDIRECT_REQUIRED result.</exception>
    public CallbackResult(CallbackResultType type, CallbackData? callbackData, string? redirectUrl)
    {
        if (type == CallbackResultType.COMPLETED && callbackData == null)
        {
            throw new ArgumentNullException(nameof(callbackData), "CallbackData cannot be null for COMPLETED result.");
        }

        if (type == CallbackResultType.REDIRECT_REQUIRED && string.IsNullOrEmpty(redirectUrl))
        {
            throw new ArgumentNullException(nameof(redirectUrl), "RedirectUrl cannot be null for REDIRECT_REQUIRED result.");
        }

        Type = type;
        CallbackData = callbackData ?? CallbackData.Empty;
        RedirectUrl = redirectUrl ?? string.Empty;
    }

    /// <summary>
    /// Gets the callback data received after authentication (COMPLETED result only).
    /// </summary>
    public CallbackData CallbackData { get; }

    /// <summary>
    /// Gets the URL to redirect to (REDIRECT_REQUIRED result only).
    /// </summary>
    public string RedirectUrl { get; }

    /// <summary>
    /// Gets the type of result of the callback execution.
    /// </summary>
    public CallbackResultType Type { get; }
}
