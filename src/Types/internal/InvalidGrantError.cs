namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents an invalid grant error returned by Wristband during token exchange or refresh.
/// </summary>
internal class InvalidGrantError : WristbandError
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidGrantError"/> class.
    /// </summary>
    /// <param name="errorDescription">The optional description of the error.</param>
    internal InvalidGrantError(string? errorDescription)
        : base("invalid_grant", errorDescription)
    {
    }
}
