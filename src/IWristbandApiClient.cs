namespace Wristband.AspNet.Auth;

/// <summary>
/// Interface for handling REST API requests to the Wristband platform.
/// </summary>
internal interface IWristbandApiClient
{
    /// <summary>
    /// Calls the Wristband Token Endpoint with the authorization code grant type to exchange an authorization code for tokens.
    /// </summary>
    /// <param name="code">The authorization code received from the OAuth2 authorization server.</param>
    /// <param name="redirectUri">The redirect URI that was specified in the auth request initially.</param>
    /// <param name="codeVerifier">The PKCE code verifier to prevent authorization code injection attacks.</param>
    /// <returns>A <see cref="Task{TokenResponse}"/> representing the asynchronous operation. The result contains the access token, refresh token, and other OAuth2 credentials.</returns>
    /// <remarks><a href="https://docs.wristband.dev/reference/tokenv1">Wristband Token Endpoint</a></remarks>
    Task<TokenResponse> GetTokens(string code, string redirectUri, string codeVerifier);

    /// <summary>
    /// Retrieves user information from the Wristband platform using the provided access token.
    /// </summary>
    /// <param name="accessToken">The access token used to authenticate the request.</param>
    /// <returns>A <see cref="Task{UserInfo}"/> representing the asynchronous operation. The result contains the user details.</returns>
    /// <remarks><a href="https://docs.wristband.dev/reference/userinfov1">Wristband UserInfo Endpoint</a></remarks>
    Task<UserInfo> GetUserinfo(string accessToken);

    /// <summary>
    /// Calls the Wristband Token Endpoint with the refresh token grant type to refresh an expired access token.
    /// </summary>
    /// <param name="refreshToken">The refresh token used to obtain a new access token.</param>
    /// <returns>A <see cref="Task{TokenResponse}"/> representing the asynchronous operation. The result contains the refreshed access token, id token, and refresh token.</returns>
    /// <remarks><a href="https://docs.wristband.dev/reference/tokenv1">Wristband Token Endpoint</a></remarks>
    Task<TokenResponse> RefreshToken(string refreshToken);

    /// <summary>
    /// Calls the Wristband Revoke Token Endpoint to revoke a refresh token.
    /// </summary>
    /// <param name="refreshToken">The refresh token to revoke.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <remarks><a href="https://docs.wristband.dev/reference/tokenv1">Wristband Token Endpoint</a></remarks>
    /// Calls the Wristband Revoke Token Endpoint. See here for more: https://docs.wristband.dev/reference/tokenv1
    Task RevokeRefreshToken(string refreshToken);
}
