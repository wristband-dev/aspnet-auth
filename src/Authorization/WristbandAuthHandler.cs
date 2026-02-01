using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Authorization handler that validates Wristband session auth and refreshes tokens if needed.
/// Sets a flag for auto-save middleware instead of calling SignInAsync directly.
/// </summary>
public class WristbandAuthHandler : AuthorizationHandler<WristbandAuthRequirement>
{
    private readonly IWristbandAuthService _wristbandAuth;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly WristbandCsrfOptions _csrfOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthHandler"/> class.
    /// </summary>
    /// <param name="wristbandAuth">The Wristband authentication service.</param>
    /// <param name="httpContextAccessor">The HTTP context accessor.</param>
    /// <param name="csrfOptions">CSRF configuration options.</param>
    public WristbandAuthHandler(
        IWristbandAuthService wristbandAuth,
        IHttpContextAccessor httpContextAccessor,
        IOptions<WristbandCsrfOptions> csrfOptions)
    {
        _wristbandAuth = wristbandAuth;
        _httpContextAccessor = httpContextAccessor;
        _csrfOptions = csrfOptions.Value;
    }

    /// <summary>
    /// Handles the authorization requirement by attempting each configured authentication strategy in order.
    /// </summary>
    /// <param name="context">The authorization handler context.</param>
    /// <param name="requirement">The Wristband authentication requirement containing strategies to try.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, WristbandAuthRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            context.Fail();
            return;
        }

        // Try each strategy in order until one succeeds
        foreach (var strategy in requirement.Strategies)
        {
            bool success = strategy switch
            {
                AuthStrategy.Session => await TrySessionAuth(httpContext),
                AuthStrategy.Jwt => await TryJwtAuth(httpContext),
                _ => false,
            };

            if (success)
            {
                context.Succeed(requirement);
                return;
            }
        }

        // All strategies failed
        context.Fail();
    }

    /// <summary>
    /// Attempts to authenticate using session-based authentication with automatic token refresh.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the current request.</param>
    /// <returns>
    /// A task that represents the asynchronous operation.
    /// The task result contains <c>true</c> if session authentication succeeded; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method:
    /// <list type="number">
    /// <item>Authenticates the session using cookie authentication</item>
    /// <item>Checks if the access token needs to be refreshed based on expiration</item>
    /// <item>Refreshes the token if needed and updates the user claims</item>
    /// <item>Sets a flag for the auto-save middleware to persist session changes</item>
    /// </list>
    /// </remarks>
    private async Task<bool> TrySessionAuth(HttpContext httpContext)
    {
        // Check session exists and is authenticated
        var authResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authResult.Succeeded || authResult.Principal == null)
        {
            return false;
        }

        // Validate CSRF token if protection is enabled
        if (_csrfOptions.EnableCsrfProtection)
        {
            var sessionToken = httpContext.User.FindFirst("csrf_token")?.Value;
            var headerToken = httpContext.Request.Headers[_csrfOptions.CsrfHeaderName].ToString();

            if (string.IsNullOrEmpty(sessionToken) || sessionToken != headerToken)
            {
                return false;
            }
        }

        var refreshToken = httpContext.GetRefreshToken();
        var expiresAt = httpContext.GetExpiresAt();

        // Only attempt refresh if we have both refreshToken and expiresAt
        if (!string.IsNullOrEmpty(refreshToken) && expiresAt.HasValue)
        {
            try
            {
                var tokenData = await _wristbandAuth.RefreshTokenIfExpired(refreshToken, expiresAt.Value);

                // Update context.User if token was refreshed
                if (tokenData != null)
                {
                    var claims = httpContext.User.Claims
                        .Where(c => !new[] { "accessToken", "refreshToken", "expiresAt" }.Contains(c.Type))
                        .Concat(
                        [
                            new Claim("accessToken", tokenData.AccessToken),
                            new Claim("expiresAt", tokenData.ExpiresAt.ToString()),
                            new Claim("refreshToken", tokenData.RefreshToken ?? string.Empty),
                        ]);

                    // Update context.User but DON'T call SignInAsync yet
                    httpContext.User = new ClaimsPrincipal(
                        new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
                }
            }
            catch (Exception)
            {
                // Token refresh errors shouldn't break the broader validation expectatios
                return false;
            }
        }

        // Set flag for auto-save middleware for rolling sessions
        httpContext.Items["WristbandSessionNeedsSave"] = true;
        return true;
    }

    /// <summary>
    /// Attempts to authenticate using JWT bearer token validation.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the current request.</param>
    /// <returns>
    /// A task that represents the asynchronous operation.
    /// The task result contains <c>true</c> if JWT validation succeeded; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method validates the JWT from the Authorization header using the Wristband JWT validator.
    /// Unlike session auth, JWT validation does not require token refresh as JWTs are stateless.
    /// </remarks>
    private async Task<bool> TryJwtAuth(HttpContext httpContext)
    {
        var authResult = await httpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
        return authResult.Succeeded && authResult.Principal != null;
    }
}
