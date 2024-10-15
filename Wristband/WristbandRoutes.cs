using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Wristband;

public static class WristbandRoutes
{
    private const string Tags = "Authentication";

    public static WebApplication MapWristbandEndpoints(this WebApplication app)
    {
        app.MapGet("/login",
                async (HttpContext httpContext, IWristbandAuthService authService) =>
                {
                    //
                    // Set some session cookie value now, so the session is created
                    // before the auth/callback redirect.
                    //
                    httpContext.Session.SetString("wristband:wristbandAuth", "true");
                    await httpContext.Session.CommitAsync();

                    var wristbandLoginUrl = await authService.Login(httpContext);
                    //
                    // In order to set cookies, this returns a regular response, not a redirect.
                    // The regular response tells the callers browser where to redirect to.
                    //
                    return Results.Ok(new { wristbandLoginUrl });
                })
            .WithTags(Tags)
            .WithOpenApi();

        app.MapGet("/logout", async (HttpContext httpContext, IWristbandAuthService authService) =>
        {
            var wristbandLogoutUrl = await authService.Logout(httpContext);
            //
            // In order to set cookies, this returns a regular response, not a redirect.
            // The regular response tells the callers browser where to redirect to.
            //
            return Results.Ok(new { wristbandLogoutUrl });
        })
        .WithTags(Tags)
        .WithOpenApi();

        app.MapGet("/auth/callback", async (HttpContext httpContext, IWristbandAuthService authService) =>
        {
            var loginFailRedirectUrl = await authService.Callback(httpContext);
            if (!string.IsNullOrEmpty(loginFailRedirectUrl))
            {
                return Results.Redirect(loginFailRedirectUrl);
            }

            //
            // Login successfully completed
            //
            var loginSuccessRedirectUrl = authService.LoginCompleted(httpContext);
            return Results.Redirect(loginSuccessRedirectUrl);
        })
        .WithTags(Tags)
        .WithOpenApi();

        app.MapGet("/auth/auth-state", (HttpContext httpContext) =>
        {
            if (httpContext.User?.Identity == null || !httpContext.User.Identity.IsAuthenticated)
            {
                return Results.Ok(new { IsAuthenticated = false, Name = "", Email = "" });
            }

            var user = httpContext.User;
            var email = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value ?? "";
            var name = user.Identity.Name ?? "";

            return Results.Ok(new 
            { 
                user.Identity.IsAuthenticated, 
                Name = name, 
                Email = email,
            });
        })
        .WithTags(Tags)
        .WithOpenApi();

        app.MapGet("/refresh-token",
                async (HttpContext httpContext, IWristbandAuthService authService) =>
                {
                    var refreshToken = WristbandAuthService.GetRefreshToken(httpContext);
                    var expiresAt = WristbandAuthService.GetExpiresAt(httpContext);
                    var tokenData =
                        await authService.RefreshTokenIfExpired(refreshToken, expiresAt);
                    if (tokenData == null)
                    {
                        return Results.BadRequest("Token refresh failed or was not necessary.");
                    }

                    await WristbandAuthService.RefreshWristbandSessionKeys(httpContext, tokenData);

                    return Results.Ok(tokenData);
                })
            .WithTags(Tags)
            .WithOpenApi();

        return app;
    }
}
