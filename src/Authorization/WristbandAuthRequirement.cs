using Microsoft.AspNetCore.Authorization;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Authorization requirement that specifies which Wristband auth strategies are allowed.
/// </summary>
public class WristbandAuthRequirement : IAuthorizationRequirement
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandAuthRequirement"/> class.
    /// </summary>
    /// <param name="strategies">The authentication strategies to allow, in order of preference.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when no strategies are specified or when duplicate strategies are provided.
    /// </exception>
    public WristbandAuthRequirement(params AuthStrategy[] strategies)
    {
        if (strategies == null || strategies.Length == 0)
        {
            throw new ArgumentException("At least one authentication strategy must be specified.", nameof(strategies));
        }

        // Detect and remove duplicates
        var uniqueStrategies = strategies.Distinct().ToArray();

        if (uniqueStrategies.Length != strategies.Length)
        {
            throw new ArgumentException("Duplicate authentication strategies are not allowed.", nameof(strategies));
        }

        Strategies = uniqueStrategies;
    }

    /// <summary>
    /// Gets the ordered list of authentication strategies to try.
    /// Strategies are attempted in the order specified until one succeeds.
    /// </summary>
    public AuthStrategy[] Strategies { get; }
}
