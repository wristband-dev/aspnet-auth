using System.Text.RegularExpressions;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Helpers for the {tenant_name} placeholder in the login and redirect URLs, and for validating return URLs.
/// </summary>
internal static class TenantUrlUtils
{
    /// <summary>
    /// The placeholder used to represent tenant subdomains in the login and redirect URLs.
    /// </summary>
    public const string TenantNamePlaceholder = "{tenant_name}";

    /// <summary>
    /// A description of the placeholder used in validation error messages.
    /// </summary>
    public const string TenantPlaceholderMessage = "\"{tenant_name}\" placeholder";

    private static readonly Regex LeadingTenantPlaceholderRegex = new(@"^https?://\{tenant_name\}\.", RegexOptions.Compiled);

    /// <summary>
    /// Derives the fallback login URL from a login URL that uses the {tenant_name} placeholder. The placeholder must be
    /// the leftmost part of the hostname, e.g. https://{tenant_name}.example.com/auth/login, and the fallback login URL
    /// is the login URL with the placeholder removed, e.g. https://example.com/auth/login.
    /// </summary>
    /// <param name="loginUrl">The application's login URL.</param>
    /// <returns>The derived fallback login URL, or an empty string when the login URL has no placeholder.</returns>
    public static string DeriveFallbackLoginUrl(string? loginUrl)
    {
        if (string.IsNullOrEmpty(loginUrl) || !loginUrl.Contains(TenantNamePlaceholder))
        {
            return string.Empty;
        }

        var placeholderIndex = loginUrl.IndexOf($"{TenantNamePlaceholder}.", StringComparison.Ordinal);
        return placeholderIndex < 0
            ? loginUrl
            : loginUrl.Remove(placeholderIndex, TenantNamePlaceholder.Length + 1);
    }

    /// <summary>
    /// Derives the root domain used for parsing tenant subdomains from a login URL that uses the {tenant_name}
    /// placeholder. The root domain is the hostname with the placeholder removed, without any port, e.g. example.com.
    /// </summary>
    /// <param name="loginUrl">The application's login URL.</param>
    /// <returns>The derived root domain, or an empty string when the login URL has no placeholder.</returns>
    public static string DeriveTenantRootDomain(string? loginUrl)
    {
        var fallbackLoginUrl = DeriveFallbackLoginUrl(loginUrl);
        return Uri.TryCreate(fallbackLoginUrl, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;
    }

    /// <summary>
    /// Checks that a URL containing the {tenant_name} placeholder has it exactly once, as the leftmost part of the
    /// hostname. URLs without the placeholder are always considered valid.
    /// </summary>
    /// <param name="url">The URL to check.</param>
    /// <returns>True if the placeholder is absent or correctly positioned.</returns>
    public static bool IsTenantPlaceholderPositionValid(string url)
    {
        if (!url.Contains(TenantNamePlaceholder))
        {
            return true;
        }

        // Removing the leading placeholder should leave no other {tenant_name} anywhere in the URL.
        return LeadingTenantPlaceholderRegex.IsMatch(url) && !DeriveFallbackLoginUrl(url).Contains(TenantNamePlaceholder);
    }

    /// <summary>
    /// Validates a user-supplied return URL to prevent open redirects. Without this, an attacker could craft a login
    /// link with return_url=https://evil.com so that a legitimate login ends with the user being sent to a site they
    /// don't control.
    /// </summary>
    /// <remarks>
    /// Relative paths resolve against the current request's host. The scheme must match the request's scheme, and the
    /// hostname must be either the root domain (when tenant subdomains are in use) or the request's host. When
    /// application-level authorization requests are enabled and tenant subdomains are in use, a return URL on the bare
    /// root domain is rewritten to the tenant's subdomain (e.g. myapp.com to acme.myapp.com).
    /// </remarks>
    /// <param name="returnUrl">The return URL from the login state cookie.</param>
    /// <param name="requestScheme">The scheme of the current request.</param>
    /// <param name="requestHost">The host of the current request, including any port.</param>
    /// <param name="tenantName">The resolved tenant name for the current callback request.</param>
    /// <param name="applicationAuthorizationRequestsEnabled">Whether app-level authorization requests are enabled.</param>
    /// <param name="rootDomain">The root domain when tenant subdomains are in use, otherwise empty.</param>
    /// <returns>The validated return URL, or null if it is missing, malformed, or points to a host that isn't allowed.</returns>
    public static string? ValidateReturnUrl(
        string? returnUrl,
        string requestScheme,
        string requestHost,
        string tenantName,
        bool applicationAuthorizationRequestsEnabled,
        string? rootDomain)
    {
        if (string.IsNullOrEmpty(tenantName))
        {
            throw new ArgumentException("Tenant name is required to validate the return URL");
        }

        if (string.IsNullOrEmpty(returnUrl))
        {
            return null;
        }

        // Without a host, the request origin cannot be established safely.
        if (string.IsNullOrEmpty(requestHost))
        {
            return null;
        }

        // Normalize the URL the same way a browser would before redirecting to it, so that tricks like "/\evil.com"
        // or "/\t/evil.com" are checked against the real redirect target.
        var normalizedUrl = NormalizeUrlLikeBrowser(returnUrl);

        if (!Uri.TryCreate($"{requestScheme}://{requestHost}", UriKind.Absolute, out var baseUri) ||
            !Uri.TryCreate(baseUri, normalizedUrl, out var resolved))
        {
            return null;
        }

        // Only allow redirects to the root domain or the exact host that served this request, over the same scheme.
        // Anything else is treated as untrusted and discarded. The scheme check blocks downgrades like https to http.
        if (!string.Equals(resolved.Scheme, baseUri.Scheme, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrEmpty(resolved.Host))
        {
            return null;
        }

        var isRequestHost = string.Equals(resolved.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase);
        var isRootDomain = !string.IsNullOrEmpty(rootDomain) &&
            string.Equals(resolved.Host, rootDomain, StringComparison.OrdinalIgnoreCase);
        if (!isRequestHost && !isRootDomain)
        {
            return null;
        }

        if (isRootDomain && applicationAuthorizationRequestsEnabled)
        {
            // The return URL points at the bare root domain, but the app expects tenant subdomains. Prepend the
            // resolved tenant so the user lands on their tenant's host. Path, query, fragment, and port are preserved.
            var builder = new UriBuilder(resolved) { Host = $"{tenantName}.{resolved.Host}" };
            return builder.Uri.AbsoluteUri;
        }

        // Allowed host and no tenant rewrite needed. Return the URL unchanged unless normalization changed it, in
        // which case return the normalized absolute URL so the browser lands exactly where we validated.
        return normalizedUrl == returnUrl ? returnUrl : resolved.AbsoluteUri;
    }

    private static string NormalizeUrlLikeBrowser(string url)
    {
        var trimmed = url.Trim(Enumerable.Range(0, 0x21).Select(c => (char)c).ToArray());
        var withoutTabsOrNewlines = trimmed.Replace("\t", string.Empty).Replace("\n", string.Empty).Replace("\r", string.Empty);
        return withoutTabsOrNewlines.Replace('\\', '/');
    }
}
