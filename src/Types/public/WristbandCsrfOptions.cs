namespace Wristband.AspNet.Auth;

/// <summary>
/// Configuration options for Wristband CSRF (Cross-Site Request Forgery) protection.
/// </summary>
/// <remarks>
/// CSRF protection uses the Synchronizer Token Pattern with dual cookies:
/// <list type="bullet">
/// <item><description>Session cookie (HttpOnly, encrypted) stores the CSRF token in claims</description></item>
/// <item><description>CSRF cookie (NOT HttpOnly) allows JavaScript to read and send the token in headers</description></item>
/// </list>
/// Enable CSRF protection by calling <see cref="WristbandCsrfExtensions.AddWristbandCsrfProtection"/> during service configuration.
/// </remarks>
public class WristbandCsrfOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether CSRF token protection is enabled for session-based authentication.
    /// When enabled, CSRF tokens are generated and validated automatically.
    /// Default: false.
    /// </summary>
    public bool EnableCsrfProtection { get; set; } = false;

    /// <summary>
    /// Gets or sets the name of the CSRF cookie (readable by JavaScript).
    /// Default: "CSRF-TOKEN".
    /// </summary>
    public string CsrfCookieName { get; set; } = "CSRF-TOKEN";

    /// <summary>
    /// Gets or sets the name of the HTTP header used to send CSRF tokens from the client.
    /// Default: "X-CSRF-TOKEN".
    /// </summary>
    public string CsrfHeaderName { get; set; } = "X-CSRF-TOKEN";

    /// <summary>
    /// Gets or sets the domain for the CSRF cookie. If null, uses the current request's domain.
    /// Use ".example.com" (with leading dot) to share across subdomains.
    /// Default: null (which means default to session cookie's domain configutation).
    /// </summary>
    public string? CsrfCookieDomain { get; set; } = null;
}
