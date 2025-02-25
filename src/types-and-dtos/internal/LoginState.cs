namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents all possible state information for the current login request, which is stored in the login state cookie.
/// </summary>
internal class LoginState
{
    /// <summary>
    /// Initializes a new instance of the <see cref="LoginState"/> class.
    /// </summary>
    /// <param name="state">The state of the login process.</param>
    /// <param name="codeVerifier">The code verifier for PKCE.</param>
    /// <param name="redirectUri">The redirect URI for callback after authentication.</param>
    /// <param name="returnUrl">The URL to return to after authentication.</param>
    /// <param name="customState">Custom state data for the login state.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <paramref name="state"/>, <paramref name="codeVerifier"/>, or <paramref name="redirectUri"/> is null or empty.
    /// </exception>
    public LoginState(
        string state,
        string codeVerifier,
        string redirectUri,
        string returnUrl,
        Dictionary<string, object>? customState)
    {
        if (string.IsNullOrEmpty(state))
        {
            throw new InvalidOperationException("[State] cannot be null or empty.");
        }

        if (string.IsNullOrEmpty(codeVerifier))
        {
            throw new InvalidOperationException("[CodeVerifier] cannot be null or empty.");
        }

        if (string.IsNullOrEmpty(redirectUri))
        {
            throw new InvalidOperationException("[RedirectUri] cannot be null or empty.");
        }

        State = state;
        CodeVerifier = codeVerifier;
        RedirectUri = redirectUri;
        ReturnUrl = returnUrl;
        CustomState = customState;
    }

    /// <summary>
    /// Gets or sets the code verifier for PKCE.
    /// </summary>
    public string CodeVerifier { get; set; }

    /// <summary>
    /// Gets or sets custom state data for the login state.
    /// </summary>
    public Dictionary<string, object>? CustomState { get; set; }

    /// <summary>
    /// Gets or sets the redirect URI for callback after authentication.
    /// </summary>
    public string RedirectUri { get; set; }

    /// <summary>
    /// Gets or sets the URL to return to after authentication.
    /// </summary>
    public string? ReturnUrl { get; set; }

    /// <summary>
    /// Gets or sets the state of the login process.
    /// </summary>
    public string State { get; set; }
}
