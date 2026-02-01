namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the full set of token, user, and login state data received after the callback completes.
/// </summary>
public class CallbackData : TokenData
{
    /// <summary>
    /// Gets an empty instance of the <see cref="CallbackData"/> class.
    /// </summary>
    public static readonly CallbackData Empty = new CallbackData(
        accessToken: "empty",
        expiresAt: 0,
        expiresIn: 0,
        idToken: "empty",
        refreshToken: null,
        userinfo: UserInfo.Empty,
        tenantName: "empty",
        tenantCustomDomain: null,
        customState: null,
        returnUrl: null);

    /// <summary>
    /// Initializes a new instance of the <see cref="CallbackData"/> class with the specified data.
    /// </summary>
    /// <param name="accessToken">The access token.</param>
    /// <param name="expiresAt">The absolute expiration time of the access token in milliseconds since the Unix epoch.</param>
    /// <param name="expiresIn">The duration from the current time until the access token is expired (in seconds).</param>
    /// <param name="idToken">The ID token.</param>
    /// <param name="refreshToken">The refresh token (optional).</param>
    /// <param name="userinfo">The user information.</param>
    /// <param name="tenantName">The name of the tenant the user belongs to.</param>
    /// <param name="tenantCustomDomain">The custom domain of the tenant (optional).</param>
    /// <param name="customState">Custom state data received in the callback (optional).</param>
    /// <param name="returnUrl">The URL to return to after authentication (optional).</param>
    /// <exception cref="InvalidOperationException">Thrown if any required field is null, empty, or invalid.</exception>
    public CallbackData(
        string accessToken,
        long expiresAt,
        int expiresIn,
        string idToken,
        string? refreshToken,
        UserInfo userinfo,
        string tenantName,
        string? tenantCustomDomain,
        Dictionary<string, object>? customState,
        string? returnUrl)
        : base(accessToken, expiresAt, expiresIn, idToken, refreshToken)
    {
        if (userinfo == null)
        {
            throw new InvalidOperationException("[Userinfo] cannot be null.");
        }

        if (string.IsNullOrEmpty(tenantName))
        {
            throw new InvalidOperationException("[TenantName] cannot be null or empty.");
        }

        Userinfo = userinfo;
        TenantName = tenantName;
        TenantCustomDomain = tenantCustomDomain;
        CustomState = customState;
        ReturnUrl = returnUrl;
    }

    /// <summary>
    /// Gets the custom state data received in the callback (optional).
    /// </summary>
    public Dictionary<string, object>? CustomState { get; }

    /// <summary>
    /// Gets the user information received in the callback.
    /// </summary>
    public UserInfo Userinfo { get; }

    /// <summary>
    /// Gets the URL to return to after authentication (optional).
    /// </summary>
    public string? ReturnUrl { get; }

    /// <summary>
    /// Gets the name of the tenant the user belongs to.
    /// </summary>
    public string TenantName { get; }

    /// <summary>
    /// Gets the custom domain of the tenant the user belongs to (optional).
    /// </summary>
    public string? TenantCustomDomain { get; }
}
