using System.Security.Claims;
using System.Text.Json;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Extension methods for managing Wristband session data in ASP.NET Core.
/// Provides convenient access to session claims, tokens, and user information
/// with automatic persistence via the session middleware.
/// </summary>
/// <remarks>
/// These extensions follow a Django/Flask-style workflow where session modifications
/// are automatically persisted after the request completes. Use SetSessionClaim() to
/// modify session data, and the WristbandSessionMiddleware will handle saving changes
/// to the encrypted cookie.
/// </remarks>
public static class WristbandSessionExtensions
{
    // ========================================
    // CONFIGURATION & MIDDLEWARE
    // ========================================

    /// <summary>
    /// Configures Wristband cookie authentication to return status codes instead of redirects to pages,
    /// which is more appropriate for API and SPA scenarios.
    /// </summary>
    /// <param name="options">The cookie authentication options.</param>
    /// <returns>The cookie authentication options for method chaining.</returns>
    public static CookieAuthenticationOptions UseWristbandApiStatusCodes(this CookieAuthenticationOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (options.Events == null)
        {
            options.Events = new CookieAuthenticationEvents();
        }

        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };

        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };

        return options;
    }

    /// <summary>
    /// Configures cookie authentication options with Wristband-recommended defaults for session management.
    /// Sets secure defaults for cookie name, security policies, and expiration behavior.
    /// </summary>
    /// <param name="options">The cookie authentication options to configure.</param>
    /// <returns>The configured cookie authentication options for chaining.</returns>
    public static CookieAuthenticationOptions UseWristbandSessionConfig(this CookieAuthenticationOptions options)
    {
        // Cookie configuration
        options.Cookie.Name = "session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.Path = "/";

        // Expiration configuration
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(1);

        // Return 401 instead of redirects for API-friendly auth
        options.UseWristbandApiStatusCodes();

        return options;
    }

    /// <summary>
    /// Adds the Wristband session middleware to the application pipeline.
    /// This middleware persists updated session data to cookies after authorization.
    /// Must be called AFTER UseAuthentication() and UseAuthorization().
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for method chaining.</returns>
    public static IApplicationBuilder UseWristbandSessionMiddleware(this IApplicationBuilder app)
    {
        return app.UseMiddleware<WristbandSessionMiddleware>();
    }

    // ========================================
    // SESSION CREATION
    // ========================================

    /// <summary>
    /// Creates a new Wristband session with the provided claims.
    /// Use this for initial session creation (e.g., after OAuth callback).
    /// For modifying existing sessions, use UpdateSessionClaim/AddSessionClaim instead.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="claims">The claims to include in the new session.</param>
    /// <example>
    /// <code>
    /// // After OAuth callback, create initial session
    /// var claims = new List&lt;Claim&gt;
    /// {
    ///     new Claim("userId", userId),
    ///     new Claim("accessToken", token),
    ///     // ... other claims
    /// };
    /// await context.CreateSession(claims);
    /// </code>
    /// </example>
    public static void CreateSession(this HttpContext context, IEnumerable<Claim> claims)
    {
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);

        // Signal middleware to save session (which will also generate CSRF token if enabled)
        context.Items["WristbandSessionNeedsSave"] = true;
    }

    /// <summary>
    /// Creates a session from Wristband callback data after successful authentication.
    /// This is a convenience method that automatically:
    /// - Extracts core user and tenant info from callback data
    /// - Marks the session for persistence in an encrypted session cookie.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="callbackData">The callback data from wristbandAuth.Callback().</param>
    /// <param name="customClaims">Optional additional claims to store in the session.</param>
    /// <example>
    /// <code>
    /// // Basic usage
    /// var callbackResult = await wristbandAuth.Callback(httpContext);
    /// await httpContext.CreateSessionFromCallback(callbackResult.CallbackData);
    ///
    /// // With custom claims
    /// await httpContext.CreateSessionFromCallback(
    ///     callbackResult.CallbackData,
    ///     customClaims: new[]
    ///     {
    ///         new Claim("role", "admin"),
    ///         new Claim("theme", "dark")
    ///     }
    /// );
    /// </code>
    /// </example>
    public static void CreateSessionFromCallback(
        this HttpContext context,
        CallbackData callbackData,
        IEnumerable<Claim>? customClaims = null)
    {
        if (callbackData == null)
        {
            throw new ArgumentNullException(nameof(callbackData));
        }

        if (callbackData.Userinfo == null)
        {
            throw new ArgumentNullException(nameof(callbackData.Userinfo));
        }

        // Build core session claims
        var claims = new List<Claim>
        {
            new Claim("isAuthenticated", "true"),
            new Claim("accessToken", callbackData.AccessToken),
            new Claim("expiresAt", callbackData.ExpiresAt.ToString()),
            new Claim("userId", callbackData.Userinfo.UserId),
            new Claim("tenantId", callbackData.Userinfo.TenantId),
            new Claim("tenantName", callbackData.TenantName),
            new Claim("identityProviderName", callbackData.Userinfo.IdentityProviderName),
        };

        // Add refreshToken only if present (offline_access scope)
        if (!string.IsNullOrEmpty(callbackData.RefreshToken))
        {
            claims.Add(new Claim("refreshToken", callbackData.RefreshToken));
        }

        // Add tenantCustomDomain only if present
        if (!string.IsNullOrEmpty(callbackData.TenantCustomDomain))
        {
            claims.Add(new Claim("tenantCustomDomain", callbackData.TenantCustomDomain));
        }

        // Add any custom claims
        if (customClaims != null)
        {
            claims.AddRange(customClaims);
        }

        // Create the session
        context.CreateSession(claims);
    }

    // ========================================
    // SESSION DESTRUCTION
    // ========================================

    /// <summary>
    /// Marks the session for destruction. The session will be destroyed by the
    /// auto-save middleware after the endpoint completes.
    /// This is preferred over calling SignOutAsync directly.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <example>
    /// <code>
    /// // Destroy session (e.g., user logout)
    /// context.DestroySession();
    /// // Session will be destroyed after endpoint completes
    /// </code>
    /// </example>
    public static void DestroySession(this HttpContext context)
    {
        context.Items["WristbandSessionNeedsDelete"] = true;
    }

    // ========================================
    // SESSION MODIFICATION
    // ========================================

    /// <summary>
    /// Sets a session claim value, adding it if it doesn't exist or updating it if it does.
    /// Automatically sets the save flag for auto-save middleware.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="key">The claim key to set.</param>
    /// <param name="value">The claim value.</param>
    /// <exception cref="InvalidOperationException">Thrown when user is not authenticated.</exception>
    /// <example>
    /// <code>
    /// // Set user preferences (adds if new, updates if exists)
    /// context.SetSessionClaim("theme", "dark");
    /// context.SetSessionClaim("language", "es");
    /// // Auto-save middleware will persist changes after endpoint completes
    /// </code>
    /// </example>
    public static void SetSessionClaim(this HttpContext context, string key, string value)
    {
        if (context.User?.Identity?.IsAuthenticated != true)
        {
            throw new InvalidOperationException(
                "Cannot set session claim. Ensure the user has an active, authenticated session.");
        }

        var claims = context.User.Claims
            .Where(c => c.Type != key)
            .Append(new Claim(key, value));

        context.User = new ClaimsPrincipal(
            new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        context.Items["WristbandSessionNeedsSave"] = true;
    }

    /// <summary>
    /// Removes a claim from the session by claim key.
    /// Automatically sets the save flag for auto-save middleware.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="key">The claim key to remove.</param>
    /// <exception cref="InvalidOperationException">Thrown when user is not authenticated.</exception>
    /// <example>
    /// <code>
    /// // Remove a feature flag
    /// context.RemoveSessionClaim("featureFlag");
    /// // Auto-save middleware will persist changes after endpoint completes
    /// </code>
    /// </example>
    public static void RemoveSessionClaim(this HttpContext context, string key)
    {
        if (context.User?.Identity?.IsAuthenticated != true)
        {
            throw new InvalidOperationException(
                "Cannot update session claim. Ensure the user has an active, authenticated session.");
        }

        var claims = context.User.Claims.Where(c => c.Type != key);

        context.User = new ClaimsPrincipal(
            new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        context.Items["WristbandSessionNeedsSave"] = true;
    }

    // ========================================
    // SESSION DATA RETRIEVAL - GENERIC
    // ========================================

    /// <summary>
    /// Gets a session claim value as a string.
    /// Returns null if the claim doesn't exist.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="key">The claim key to retrieve.</param>
    /// <returns>The claim value as a string, or null if not found.</returns>
    /// <example>
    /// <code>
    /// var userId = context.GetSessionClaim("userId");
    /// var email = context.GetSessionClaim("email") ?? "unknown@example.com";
    /// var customValue = context.GetSessionClaim("myCustomClaim");
    /// </code>
    /// </example>
    public static string? GetSessionClaim(this HttpContext context, string key)
    {
        return context.User.FindFirst(key)?.Value;
    }

    // ========================================
    // TYPED GETTERS FOR KNOWN WRISTBAND FIELDS
    // ========================================

    /// <summary>
    /// Gets whether the user is authenticated.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns><c>true</c> if the user is authenticated; otherwise, <c>false</c>.</returns>
    public static bool IsAuthenticated(this HttpContext context)
    {
        var value = context.GetSessionClaim("isAuthenticated");
        return value == "true";
    }

    /// <summary>
    /// Gets the access token from the session.
    /// Returns null if not present.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The access token, or null if not present.</returns>
    public static string? GetAccessToken(this HttpContext context)
    {
        return context.GetSessionClaim("accessToken");
    }

    /// <summary>
    /// Gets the refresh token from the session.
    /// Returns null if not present (no offline_access scope).
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The refresh token, or null if not present.</returns>
    public static string? GetRefreshToken(this HttpContext context)
    {
        return context.GetSessionClaim("refreshToken");
    }

    /// <summary>
    /// Gets the token expiration timestamp from the session.
    /// Returns null if not present or invalid.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The token expiration timestamp in milliseconds since Unix epoch, or null if not present.</returns>
    public static long? GetExpiresAt(this HttpContext context)
    {
        var value = context.GetSessionClaim("expiresAt");
        return long.TryParse(value, out var expiresAt) ? expiresAt : null;
    }

    /// <summary>
    /// Gets the user ID from the session.
    /// Returns null if not present.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The user ID, or null if not present.</returns>
    public static string? GetUserId(this HttpContext context)
    {
        return context.GetSessionClaim("userId");
    }

    /// <summary>
    /// Gets the tenant ID from the session.
    /// Returns null if not present.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The tenant ID, or null if not present.</returns>
    public static string? GetTenantId(this HttpContext context)
    {
        return context.GetSessionClaim("tenantId");
    }

    /// <summary>
    /// Gets the tenant name from the session.
    /// Returns null if not present.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The tenant name, or null if not present.</returns>
    public static string? GetTenantName(this HttpContext context)
    {
        return context.GetSessionClaim("tenantName");
    }

    /// <summary>
    /// Gets the identity provider name from the session.
    /// Returns null if not present.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The identity provider name, or null if not present.</returns>
    public static string? GetIdentityProviderName(this HttpContext context)
    {
        return context.GetSessionClaim("identityProviderName");
    }

    /// <summary>
    /// Gets the tenant custom domain from the session.
    /// Returns null if no custom domain was used during authentication.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>The tenant custom domain, or null if not present.</returns>
    public static string? GetTenantCustomDomain(this HttpContext context)
    {
        return context.GetSessionClaim("tenantCustomDomain");
    }

    /// <summary>
    /// Gets the roles assigned to the user from the session.
    /// Deserializes the roles from the JSON-encoded "Roles" claim.
    /// Returns an empty list if roles claim is missing or deserialization fails.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>List of UserInfoRole objects.</returns>
    /// <example>
    /// <code>
    /// var roles = httpContext.GetRoles();
    /// foreach (var role in roles)
    /// {
    ///     Console.WriteLine($"{role.DisplayName}: {role.Name}");
    /// }
    /// </code>
    /// </example>
    public static List<UserInfoRole> GetRoles(this HttpContext context)
    {
        var rolesJson = context.GetSessionClaim("roles");

        if (string.IsNullOrEmpty(rolesJson))
        {
            return new List<UserInfoRole>();
        }

        try
        {
            return JsonSerializer.Deserialize<List<UserInfoRole>>(rolesJson) ?? new List<UserInfoRole>();
        }
        catch
        {
            return new List<UserInfoRole>();
        }
    }

    // ========================================
    // FRONTEND SDK RESPONSES
    // ========================================

    /// <summary>
    /// Creates a session response for Wristband frontend SDKs.
    /// Returns user and tenant IDs with optional custom metadata.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="metadata">Optional custom metadata to include in the response (must be JSON-serializable).</param>
    /// <returns>A SessionResponse object containing userId, tenantId, and metadata.</returns>
    /// <example>
    /// <code>
    /// app.MapGet("/session", (HttpContext httpContext) =>
    /// {
    ///     var response = httpContext.GetSessionResponse(metadata: new
    ///     {
    ///         email = httpContext.GetSessionClaim("email"),
    ///         fullName = httpContext.GetSessionClaim("fullName")
    ///     });
    ///     return Results.Ok(response);
    /// })
    /// .RequireWristbandSession();
    /// </code>
    /// </example>
    public static SessionResponse GetSessionResponse(this HttpContext context, object? metadata = null)
    {
        var userId = context.GetUserId();
        var tenantId = context.GetTenantId();

        if (string.IsNullOrEmpty(userId))
        {
            throw new InvalidOperationException("Session is missing required userId");
        }

        if (string.IsNullOrEmpty(tenantId))
        {
            throw new InvalidOperationException("Session is missing required tenantId");
        }

        // Set no-cache headers (required for Wristband frontend SDKs)
        context.Response.Headers["Cache-Control"] = "no-store";
        context.Response.Headers["Pragma"] = "no-cache";

        return new SessionResponse
        {
            UserId = userId,
            TenantId = tenantId,
            Metadata = metadata,
        };
    }

    /// <summary>
    /// Creates a token response for Wristband frontend SDKs.
    /// Returns the access token and its expiration time.
    /// This is typically used in a Token Endpoint when your frontend needs direct access to tokens.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>A TokenResponse object containing accessToken and expiresAt.</returns>
    /// <example>
    /// <code>
    /// app.MapGet("/token", (HttpContext httpContext) =>
    /// {
    ///     var response = httpContext.GetTokenResponse();
    ///     return Results.Ok(response);
    /// })
    /// .RequireWristbandSession();
    /// </code>
    /// </example>
    public static TokenResponse GetTokenResponse(this HttpContext context)
    {
        var accessToken = context.GetAccessToken();
        var expiresAt = context.GetExpiresAt();

        if (string.IsNullOrEmpty(accessToken))
        {
            throw new InvalidOperationException("Session is missing required accessToken");
        }

        if (!expiresAt.HasValue || expiresAt.Value < 0)
        {
            throw new InvalidOperationException("Session is missing required expiresAt");
        }

        // Set no-cache headers (required for Wristband frontend SDKs)
        context.Response.Headers["Cache-Control"] = "no-store";
        context.Response.Headers["Pragma"] = "no-cache";

        return new TokenResponse
        {
            AccessToken = accessToken,
            ExpiresAt = expiresAt.Value,
        };
    }
}
