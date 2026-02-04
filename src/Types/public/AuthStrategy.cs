namespace Wristband.AspNet.Auth;

/// <summary>
/// Authentication strategies supported by Wristband.
/// Uses [Flags] to allow multi-strategy combinations in the future.
/// </summary>
[Flags]
public enum AuthStrategy
{
    /// <summary>
    /// Session-based authentication using cookies.
    /// </summary>
    Session = 1,

    /// <summary>
    /// JWT bearer token authentication.
    /// </summary>
    Jwt = 2,
}
