using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Extension methods for applying Wristband authorization to endpoints.
/// </summary>
public static class WristbandEndpointExtensions
{
    // ========================================
    // INDIVIDUAL ENDPOINT METHODS
    // ========================================

    /// <summary>
    /// Requires Wristband session-based authentication for this endpoint.
    /// </summary>
    /// <param name="builder">The route handler builder.</param>
    /// <returns>The route handler builder for chaining.</returns>
    public static RouteHandlerBuilder RequireWristbandSession(this RouteHandlerBuilder builder)
    {
        return builder.RequireAuthorization("WristbandSession");
    }

    /// <summary>
    /// Requires JWT-based Wristband authentication for this endpoint.
    /// Delegates to <see cref="Jwt.WristbandJwtValidationExtensions.RequireWristbandJwt(RouteHandlerBuilder)"/>.
    /// </summary>
    /// <param name="builder">The route handler builder.</param>
    /// <returns>The route handler builder for chaining.</returns>
    public static RouteHandlerBuilder RequireWristbandJwt(this RouteHandlerBuilder builder)
    {
        return Jwt.WristbandJwtValidationExtensions.RequireWristbandJwt(builder);
    }

    /// <summary>
    /// Requires Wristband multi-strategy authentication for this endpoint.
    /// Uses the "WristbandMultiAuth" policy registered via AddWristbandMultiStrategyPolicy().
    /// </summary>
    /// <param name="builder">The route handler builder.</param>
    /// <returns>The route handler builder for chaining.</returns>
    public static RouteHandlerBuilder RequireWristbandMultiAuth(this RouteHandlerBuilder builder)
    {
        return builder.RequireAuthorization("WristbandMultiAuth");
    }

    // ========================================
    // ROUTE GROUP METHODS
    // ========================================

    /// <summary>
    /// Requires Wristband session-based authentication for all endpoints in this route group.
    /// </summary>
    /// <param name="group">The route group builder.</param>
    /// <returns>The route group builder for chaining.</returns>
    public static RouteGroupBuilder RequireWristbandSession(this RouteGroupBuilder group)
    {
        return group.RequireAuthorization("WristbandSession");
    }

    /// <summary>
    /// Requires JWT-based Wristband authentication for all endpoints in this route group.
    /// Delegates to <see cref="Jwt.WristbandJwtValidationExtensions.RequireWristbandJwt(RouteGroupBuilder)"/>.
    /// </summary>
    /// <param name="group">The route group builder.</param>
    /// <returns>The route group builder for chaining.</returns>
    public static RouteGroupBuilder RequireWristbandJwt(this RouteGroupBuilder group)
    {
        return Jwt.WristbandJwtValidationExtensions.RequireWristbandJwt(group);
    }

    /// <summary>
    /// Requires Wristband multi-strategy authentication for all endpoints in this route group.
    /// Uses the "WristbandMultiAuth" policy registered via AddWristbandMultiStrategyPolicy().
    /// </summary>
    /// <param name="group">The route group builder.</param>
    /// <returns>The route group builder for chaining.</returns>
    public static RouteGroupBuilder RequireWristbandMultiAuth(this RouteGroupBuilder group)
    {
        return group.RequireAuthorization("WristbandMultiAuth");
    }
}
