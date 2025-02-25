using System;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Indicates that the endpoint requires Wristband authentication.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public class RequireWristbandAuth : Attribute
{
    // Marker attribute to indicate Wristband authentication is required
}
