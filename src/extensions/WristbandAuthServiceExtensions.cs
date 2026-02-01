using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Extension methods for configuring Wristband authentication services.
/// </summary>
public static class WristbandAuthServiceExtensions
{
    /// <summary>
    /// Adds Wristband authentication services to the service collection using direct configuration.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configureOptions">A delegate to configure the <see cref="WristbandAuthConfig"/>.</param>
    /// <param name="httpClientFactory">Optional external HTTP client factory.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddWristbandAuth(
        this IServiceCollection services,
        Action<WristbandAuthConfig> configureOptions,
        IHttpClientFactory? httpClientFactory = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.Configure(configureOptions);
        services.AddSingleton<IWristbandAuthService>(serviceProvider =>
        {
            var authConfig = serviceProvider.GetRequiredService<IOptions<WristbandAuthConfig>>().Value;

            // Use explicitly provided factory or try to get from DI; null will trigger fallback to internal factory
            var factory = httpClientFactory ?? serviceProvider.GetService<IHttpClientFactory>();
            return new WristbandAuthService(authConfig, factory);
        });

        // Register the service factory if not already registered
        services.TryAddSingleton<WristbandAuthServiceFactory>();

        return services;
    }

    /// <summary>
    /// Adds a named Wristband authentication service to the service collection using direct configuration.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="name">The name of the auth service instance.</param>
    /// <param name="configureOptions">A delegate to configure the <see cref="WristbandAuthConfig"/>.</param>
    /// <param name="httpClientFactory">Optional external HTTP client factory.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddWristbandAuth(
        this IServiceCollection services,
        string name,
        Action<WristbandAuthConfig> configureOptions,
        IHttpClientFactory? httpClientFactory = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(configureOptions);

        // Configure the named options
        services.Configure(name, configureOptions);

        // Register the named service
        services.AddSingleton(sp =>
        {
            var optionsMonitor = sp.GetRequiredService<IOptionsMonitor<WristbandAuthConfig>>();
            var options = new OptionsWrapper<WristbandAuthConfig>(optionsMonitor.Get(name));

            // Create the named client with its specific factory if provided
            var factory = httpClientFactory ?? sp.GetService<IHttpClientFactory>();
            return new NamedWristbandAuthService(name, options, factory);
        });

        // Register the service factory if not already registered
        services.TryAddSingleton<WristbandAuthServiceFactory>();

        return services;
    }
}
