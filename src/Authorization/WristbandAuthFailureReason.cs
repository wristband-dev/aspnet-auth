using Microsoft.AspNetCore.Authorization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// The reason a Wristband auth strategy failed, recorded on the authorization result so that the response can use
/// the matching status code: 403 for <see cref="CsrfFailed"/>, otherwise 401.
/// </summary>
public class WristbandAuthFailureReason : AuthorizationFailureReason
{
    /// <summary>
    /// The request carries no valid credential (e.g. no session, or an expired or invalid Bearer token).
    /// </summary>
    public const string NotAuthenticated = "not_authenticated";

    /// <summary>
    /// The session is valid, but the CSRF header is missing or doesn't match the session's CSRF token.
    /// </summary>
    public const string CsrfFailed = "csrf_failed";

    /// <summary>
    /// The session's access token expired and could not be refreshed.
    /// </summary>
    public const string TokenRefreshFailed = "token_refresh_failed";

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthFailureReason"/> class.
    /// </summary>
    /// <param name="handler">The authorization handler that recorded the failure.</param>
    /// <param name="reason">The failure reason, e.g. <see cref="NotAuthenticated"/>.</param>
    public WristbandAuthFailureReason(IAuthorizationHandler handler, string reason)
        : base(handler, reason)
    {
        Reason = reason;
    }

    /// <summary>
    /// Gets the failure reason, e.g. <see cref="NotAuthenticated"/>.
    /// </summary>
    public string Reason { get; }
}
