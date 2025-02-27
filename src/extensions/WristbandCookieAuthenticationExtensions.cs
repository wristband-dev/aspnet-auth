using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Extension methods for configuring Wristband cookie authentication options in ASP.NET Core applications.
/// Provides customizations specific to the Wristband authentication workflow.
/// </summary>
public static class WristbandCookieAuthenticationExtensions
{
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

        return options;
    }
}
