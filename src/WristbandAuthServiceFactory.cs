using Microsoft.Extensions.DependencyInjection;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Factory for retrieving named Wristband authentication services.
/// </summary>
public class WristbandAuthServiceFactory
{
    private readonly IServiceProvider _serviceProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthServiceFactory"/> class.
    /// </summary>
    /// <param name="serviceProvider">The service provider.</param>
    public WristbandAuthServiceFactory(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
    }

    /// <summary>
    /// Gets a named Wristband authentication service.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <returns>The named Wristband authentication service.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no service with the specified name is registered.</exception>
    public IWristbandAuthService GetService(string name)
    {
        // Get all services and find the one with the matching name
        var services = _serviceProvider.GetServices<NamedWristbandAuthService>();
        var service = services.FirstOrDefault(s => s.Name == name);

        if (service == null)
        {
            throw new InvalidOperationException($"No auth service registered with name '{name}'");
        }

        return service;
    }
}
