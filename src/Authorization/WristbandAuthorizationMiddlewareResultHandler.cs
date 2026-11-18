using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Chooses the response for a failed Wristband auth strategy from its <see cref="WristbandAuthFailureReason"/>,
/// instead of from whether the request was authenticated: a CSRF failure forbids the request (403), and any other
/// failure challenges it (401). The default handler then sends the response through the policy's authentication
/// schemes, so your cookie and JWT bearer events (e.g. UseWristbandApiStatusCodes()) still apply.
/// </summary>
internal class WristbandAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    /// <inheritdoc />
    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        var failureReason = authorizeResult.AuthorizationFailure?.FailureReasons
            .OfType<WristbandAuthFailureReason>()
            .FirstOrDefault();

        if (!authorizeResult.Succeeded && failureReason != null)
        {
            authorizeResult = failureReason.Reason == WristbandAuthFailureReason.CsrfFailed
                ? PolicyAuthorizationResult.Forbid(authorizeResult.AuthorizationFailure)
                : PolicyAuthorizationResult.Challenge();
        }

        return _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }
}
