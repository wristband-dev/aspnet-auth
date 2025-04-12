using Microsoft.Extensions.Options;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Named implementation of the Wristband authentication service.
/// </summary>
public class NamedWristbandAuthService : WristbandAuthService
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NamedWristbandAuthService"/> class.
    /// </summary>
    /// <param name="name">The name of the service.</param>
    /// <param name="options">The options for this service.</param>
    /// <param name="httpClientFactory">Optional HTTP client factory.</param>
    public NamedWristbandAuthService(
        string name,
        IOptions<WristbandAuthConfig> options,
        IHttpClientFactory? httpClientFactory = null)
        : base(options.Value, httpClientFactory)
    {
        Name = name;
    }

    /// <summary>
    /// Gets the name of this client instance.
    /// </summary>
    public string Name { get; }
}
