namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents an error returned by Wristband, typically for cases that can be handled by your application.
/// </summary>
public class WristbandError : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="WristbandError"/> class with the specified error code and description.
    /// </summary>
    /// <param name="error">The error code associated with the error.</param>
    /// <param name="errorDescription">The optional description of the error.</param>
    public WristbandError(string error, string? errorDescription)
        : base(error)
    {
        Error = error;
        ErrorDescription = errorDescription ?? string.Empty;
    }

    /// <summary>
    /// Gets the error code associated with the error.
    /// </summary>
    public string Error { get; }

    /// <summary>
    /// Gets the description of the error.
    /// </summary>
    public string ErrorDescription { get; }
}
