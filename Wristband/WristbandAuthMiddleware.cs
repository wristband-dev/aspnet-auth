using Microsoft.AspNetCore.Http;

namespace Wristband;

public class WristbandAuthMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, IWristbandAuthService wristbandAuth)
    {
        var isAuthenticated = WristbandAuthService.GetIsAuthenticated(context);
        if (isAuthenticated)
        {
            try
            {
                var refreshToken = WristbandAuthService.GetRefreshToken(context);
                var expiresAt = WristbandAuthService.GetExpiresAt(context);
                var tokenData = await wristbandAuth.RefreshTokenIfExpired(refreshToken, expiresAt);
                if (tokenData != null)
                {
                    await WristbandAuthService.RefreshWristbandSessionKeys(context, tokenData);
                }
            }
            catch (Exception error)
            {
                await Console.Error.WriteLineAsync($"Failed to refresh token due to: {error}");
                context.Response.StatusCode = 401;
            }
        }

        await next(context);
    }
}
