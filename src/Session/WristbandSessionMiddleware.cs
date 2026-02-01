using System.Security.Claims;
using System.Security.Cryptography;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Middleware that saves session changes after the request completes.
/// Uses the same pattern as Microsoft's SessionMiddleware.CommitAsync().
/// </summary>
public class WristbandSessionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly WristbandCsrfOptions _csrfOptions;
    private readonly CookieAuthenticationOptions _sessionCookieOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandSessionMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="csrfOptions">CSRF configuration options.</param>
    /// <param name="cookieOptionsMonitor">Session cookie configuration options.</param>
    public WristbandSessionMiddleware(
        RequestDelegate next,
        IOptions<WristbandCsrfOptions> csrfOptions,
        IOptionsMonitor<CookieAuthenticationOptions> cookieOptionsMonitor)
    {
        _next = next;
        _csrfOptions = csrfOptions.Value;
        _sessionCookieOptions = cookieOptionsMonitor.Get(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Invokes the middleware to handle session auto-save and destruction.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext ctx)
    {
        ctx.Response.OnStarting(async () => await CommitSessionAsync(ctx));
        await _next(ctx);
    }

    /// <summary>
    /// Commits session changes based on flags set in HttpContext.Items.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    internal async Task CommitSessionAsync(HttpContext ctx)
    {
        // PRIORITY 1: Destroy session if requested (takes precedence over save)
        if (ctx.Items.TryGetValue("WristbandSessionNeedsDelete", out var needsDelete) && needsDelete is true)
        {
            await HandleSessionDeletion(ctx);
        }

        // PRIORITY 2: Save session if modified
        else if (ctx.Items.TryGetValue("WristbandSessionNeedsSave", out var needsSave) && needsSave is true)
        {
            await HandleSessionSave(ctx);
        }

        // PRIORITY 3: Convert 401 to 403 for CSRF failures
        HandleCsrfFailureStatusCode(ctx);
    }

    /// <summary>
    /// Handles session deletion and CSRF cookie cleanup.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    internal async Task HandleSessionDeletion(HttpContext ctx)
    {
        await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Delete CSRF cookie if CSRF protection is enabled
        if (_csrfOptions.EnableCsrfProtection)
        {
            ctx.Response.Cookies.Delete(_csrfOptions.CsrfCookieName);
        }
    }

    /// <summary>
    /// Handles session save, including CSRF token generation and cookie updates.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    internal async Task HandleSessionSave(HttpContext ctx)
    {
        // Generate CSRF token if enabled and not already present
        if (_csrfOptions.EnableCsrfProtection)
        {
            HandleCsrfTokenGeneration(ctx);
        }

        // User claims already updated by handler/extensions
        await ctx.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            ctx.User,
            new AuthenticationProperties { IsPersistent = true });
    }

    /// <summary>
    /// Generates or updates CSRF token and cookie.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    internal void HandleCsrfTokenGeneration(HttpContext ctx)
    {
        var existingToken = ctx.User.FindFirst("csrf_token")?.Value;

        if (string.IsNullOrEmpty(existingToken))
        {
            var newToken = CreateCsrfToken();
            AddCsrfTokenToSession(ctx, newToken);
            UpdateCsrfCookie(ctx, newToken);
        }
        else
        {
            UpdateCsrfCookie(ctx, existingToken);
        }
    }

    /// <summary>
    /// Converts 401 to 403 when CSRF validation fails.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    internal void HandleCsrfFailureStatusCode(HttpContext ctx)
    {
        if (_csrfOptions.EnableCsrfProtection &&
            ctx.Response.StatusCode == 401 &&
            ctx.Items.TryGetValue("WristbandCsrfFailure", out var csrfFailure) &&
            csrfFailure is true)
        {
            ctx.Response.StatusCode = 403;
        }
    }

    /// <summary>
    /// Creates a cryptographically secure CSRF token.
    /// </summary>
    /// <returns>A 32-character hexadecimal string representing the CSRF token.</returns>
    internal string CreateCsrfToken()
    {
        var secretBytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToHexString(secretBytes).ToLower();
    }

    /// <summary>
    /// Adds CSRF token to user claims.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    /// <param name="csrfToken">The CSRF token to add to the session.</param>
    internal void AddCsrfTokenToSession(HttpContext ctx, string csrfToken)
    {
        var claims = ctx.User.Claims.Append(new Claim("csrf_token", csrfToken));
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
    }

    /// <summary>
    /// Updates the CSRF cookie with proper security settings.
    /// </summary>
    /// <param name="ctx">The HTTP context for the current request.</param>
    /// <param name="csrfToken">The CSRF token value to set in the cookie.</param>
    internal void UpdateCsrfCookie(HttpContext ctx, string csrfToken)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = false, // NOT HttpOnly - JavaScript can read it
            Secure = _sessionCookieOptions.Cookie.SecurePolicy switch
            {
                CookieSecurePolicy.Always => true,
                CookieSecurePolicy.None => false,
                CookieSecurePolicy.SameAsRequest => ctx.Request.IsHttps,
                _ => true,
            },
            SameSite = _sessionCookieOptions.Cookie.SameSite == SameSiteMode.Unspecified
                ? SameSiteMode.Lax
                : _sessionCookieOptions.Cookie.SameSite,
            Path = _sessionCookieOptions.Cookie.Path ?? "/",
            Domain = _csrfOptions.CsrfCookieDomain ?? _sessionCookieOptions.Cookie.Domain,
            Expires = DateTimeOffset.UtcNow.Add(_sessionCookieOptions.ExpireTimeSpan),
        };

        ctx.Response.Cookies.Append(_csrfOptions.CsrfCookieName, csrfToken, cookieOptions);
    }
}
