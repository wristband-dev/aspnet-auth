using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Extension methods for accessing JWT data from HttpContext.
/// These methods re-export the context extensions from the aspnet-jwt package,
/// allowing aspnet-auth users to access JWT helpers without requiring an additional using statement.
/// </summary>
public static class WristbandContextExtensions
{
    /// <summary>
    /// Gets the raw JWT token from the Authorization header.
    /// This method delegates to the aspnet-jwt package implementation.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The JWT token string, or null if not present.</returns>
    /// <example>
    /// <code>
    /// app.MapGet("/api/data", (HttpContext context) =>
    /// {
    ///     var jwt = context.GetJwt();
    ///     return Results.Ok(new { token = jwt });
    /// })
    /// .RequireWristbandJwt();
    /// </code>
    /// </example>
    public static string? GetJwt(this HttpContext context)
    {
        return Jwt.WristbandJwtContextExtensions.GetJwt(context);
    }

    /// <summary>
    /// Gets the validated JWT payload from the authenticated user's claims.
    /// This method delegates to the aspnet-jwt package implementation.
    /// Assumes JWT authentication has already been performed and the user is authenticated.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The JWT payload object containing all claims.</returns>
    /// <example>
    /// <code>
    /// app.MapGet("/api/user", (HttpContext context) =>
    /// {
    ///     var payload = context.GetJwtPayload();
    ///     var userId = payload.Sub;
    ///     var tenantId = payload.Claims?["tnt_id"];
    ///     return Results.Ok(new { userId, tenantId });
    /// })
    /// .RequireWristbandJwt();
    /// </code>
    /// </example>
    public static Jwt.JWTPayload GetJwtPayload(this HttpContext context)
    {
        return Jwt.WristbandJwtContextExtensions.GetJwtPayload(context);
    }
}
