using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Extension methods for configuring Wristband authentication services.
/// </summary>
public static class WristbandAuthServiceExtensions
{
    /// <summary>
    /// Adds Wristband authentication services to the service collection using configuration settings.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configuration">The configuration instance to read settings from.</param>
    /// <param name="configSectionName">The configuration section name for Wristband auth settings. Defaults to "WristbandAuthConfig".</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddWristbandAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        string configSectionName = "WristbandAuthConfig")
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<WristbandAuthConfig>(configuration.GetSection(configSectionName));
        services.AddScoped<IWristbandAuthService>(serviceProvider =>
        {
            var authConfig = serviceProvider.GetRequiredService<IOptions<WristbandAuthConfig>>().Value;
            return new WristbandAuthService(authConfig);
        });

        return services;
    }

    /// <summary>
    /// Adds Wristband authentication services to the service collection using direct configuration.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configureOptions">A delegate to configure the <see cref="WristbandAuthConfig"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddWristbandAuth(
        this IServiceCollection services,
        Action<WristbandAuthConfig> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.Configure(configureOptions);
        services.AddScoped<IWristbandAuthService>(serviceProvider =>
        {
            var authConfig = serviceProvider.GetRequiredService<IOptions<WristbandAuthConfig>>().Value;
            return new WristbandAuthService(authConfig);
        });

        return services;
    }
}
