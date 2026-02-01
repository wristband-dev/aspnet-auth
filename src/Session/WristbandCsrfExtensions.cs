using Microsoft.Extensions.DependencyInjection;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Extension methods for configuring Wristband CSRF protection.
/// </summary>
public static class WristbandCsrfExtensions
{
    /// <summary>
    /// Enables CSRF protection for Wristband session-based authentication.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configuration callback for CSRF options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddWristbandCsrfProtection(
        this IServiceCollection services,
        Action<WristbandCsrfOptions>? configure = null)
    {
        services.Configure<WristbandCsrfOptions>(options =>
        {
            options.EnableCsrfProtection = true;
            configure?.Invoke(options);
        });

        return services;
    }
}
