using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Authorization handler that validates Wristband session auth and refreshes tokens if needed.
/// Sets a flag for auto-save middleware instead of calling SignInAsync directly.
/// </summary>
public class WristbandAuthHandler : AuthorizationHandler<WristbandAuthRequirement>
{
    private const string DefaultSessionCookieName = "session";

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
    /// Handles the authorization requirement by checking each configured authentication strategy in order.
    /// </summary>
    /// <remarks>
    /// A strategy is skipped when the request doesn't carry its credential: no session cookie for SESSION, or no
    /// Authorization header for JWT. When a credential is present but fails, the requirement fails right away with
    /// that strategy's <see cref="WristbandAuthFailureReason"/>, and later strategies aren't tried. When every
    /// strategy is skipped, the requirement fails with <see cref="WristbandAuthFailureReason.NotAuthenticated"/>.
    /// </remarks>
    /// <param name="context">The authorization handler context.</param>
    /// <param name="requirement">The Wristband authentication requirement containing strategies to check.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, WristbandAuthRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext == null)
        {
            context.Fail();
            return;
        }

        // Check the auth strategies in sequential order
        foreach (var strategy in requirement.Strategies)
        {
            // Skip to the next strategy when the request doesn't carry this strategy's credential.
            if (!HasCredential(httpContext, strategy))
            {
                continue;
            }

            // The credential is present, so its result is final: later strategies aren't tried.
            var failureReason = strategy switch
            {
                AuthStrategy.Session => await TrySessionAuth(httpContext),
                AuthStrategy.Jwt => await TryJwtAuth(httpContext),
                _ => WristbandAuthFailureReason.NotAuthenticated,
            };

            if (failureReason == null)
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail(new WristbandAuthFailureReason(this, failureReason));
            }

            return;
        }

        // Every strategy was skipped because the request carried no credentials.
        context.Fail(new WristbandAuthFailureReason(this, WristbandAuthFailureReason.NotAuthenticated));
    }

    /// <summary>
    /// Checks whether the request carries the credential for an auth strategy: a session cookie for SESSION, or an
    /// Authorization header for JWT. Only presence is checked, not validity.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the current request.</param>
    /// <param name="strategy">The auth strategy to check.</param>
    /// <returns><c>true</c> if the credential is present; otherwise, <c>false</c>.</returns>
    private static bool HasCredential(HttpContext httpContext, AuthStrategy strategy)
    {
        return strategy switch
        {
            AuthStrategy.Session => httpContext.Request.Cookies.ContainsKey(GetSessionCookieName(httpContext)),
            AuthStrategy.Jwt => !string.IsNullOrEmpty(httpContext.Request.Headers.Authorization.ToString()),
            _ => false,
        };
    }

    /// <summary>
    /// Gets the session cookie name from the cookie authentication options, which UseWristbandSessionConfig() sets
    /// to "session". A session too large for one cookie is split into chunks, but the first chunk keeps this name.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the current request.</param>
    /// <returns>The session cookie name.</returns>
    private static string GetSessionCookieName(HttpContext httpContext)
    {
        var cookieOptions = httpContext.RequestServices?
            .GetService<IOptionsMonitor<CookieAuthenticationOptions>>()?
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        return cookieOptions?.Cookie.Name ?? DefaultSessionCookieName;
    }

    /// <summary>
    /// Compares the session's CSRF token to the request header's in constant time, so that the time taken doesn't
    /// reveal how much of the header value matched.
    /// </summary>
    /// <param name="sessionToken">The CSRF token stored in the session.</param>
    /// <param name="headerToken">The CSRF token sent in the request header.</param>
    /// <returns><c>true</c> if the tokens are equal; otherwise, <c>false</c>.</returns>
    private static bool CsrfTokensMatch(string sessionToken, string headerToken)
    {
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(sessionToken),
            Encoding.UTF8.GetBytes(headerToken));
    }

    /// <summary>
    /// Attempts to authenticate using session-based authentication with automatic token refresh.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the current request.</param>
    /// <returns>
    /// A task that represents the asynchronous operation.
    /// The task result is <c>null</c> if session authentication succeeded; otherwise, the failure reason.
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
    private async Task<string?> TrySessionAuth(HttpContext httpContext)
    {
        // Check session exists and is authenticated
        var authResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authResult.Succeeded || authResult.Principal == null)
        {
            return WristbandAuthFailureReason.NotAuthenticated;
        }

        // Validate CSRF token if protection is enabled
        if (_csrfOptions.EnableCsrfProtection)
        {
            var sessionToken = httpContext.User.FindFirst("csrf_token")?.Value;
            var headerToken = httpContext.Request.Headers[_csrfOptions.CsrfHeaderName].ToString();

            if (string.IsNullOrEmpty(sessionToken) || !CsrfTokensMatch(sessionToken, headerToken))
            {
                httpContext.Items["WristbandCsrfFailure"] = true;
                return WristbandAuthFailureReason.CsrfFailed;
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
                // Token refresh errors shouldn't break the broader validation expectations
                return WristbandAuthFailureReason.TokenRefreshFailed;
            }
        }

        // Set flag for auto-save middleware for rolling sessions
        httpContext.Items["WristbandSessionNeedsSave"] = true;
        return null;
    }

    /// <summary>
    /// Attempts to authenticate using JWT bearer token validation.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the current request.</param>
    /// <returns>
    /// A task that represents the asynchronous operation.
    /// The task result is <c>null</c> if JWT validation succeeded; otherwise, the failure reason.
    /// </returns>
    /// <remarks>
    /// This method validates the JWT from the Authorization header using the Wristband JWT validator.
    /// Unlike session auth, JWT validation does not require token refresh as JWTs are stateless.
    /// </remarks>
    private async Task<string?> TryJwtAuth(HttpContext httpContext)
    {
        var authResult = await httpContext.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
        return authResult.Succeeded && authResult.Principal != null ? null : WristbandAuthFailureReason.NotAuthenticated;
    }
}
