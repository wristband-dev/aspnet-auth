using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Provides methods for seamless interaction with Wristband for authenticating application users.
/// This interface includes functionality to handle login, logout, callback processing, and token refresh.
/// </summary>
public interface IWristbandAuthService
{
    /// <summary>
    /// Immediately fetch and resolve all auto-configuration values from the Wristband SDK Configuration Endpoint.
    /// This is useful when you want to fail fast if auto-configuration is unavailable, or when you need configuration
    /// values resolved before making any auth method calls. Manual configuration values take precedence over
    /// auto-configured values.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="WristbandError">Thrown when auto-configure is disabled or configuration fails.</exception>
    Task Discover();

    /// <summary>
    /// Generates the authorization URL for initiating a login request with Wristband.
    /// </summary>
    /// <param name="context">The HTTP context for the request, containing details about the login request.</param>
    /// <param name="loginConfig">Optional configuration for customizing the login request.</param>
    /// <returns>A task representing the asynchronous operation, containing the login redirect URL.</returns>
    /// <exception cref="Exception">Thrown if an error occurs during the login process.</exception>
    Task<string> Login(HttpContext context, LoginConfig? loginConfig);

    /// <summary>
    /// Handles the callback from Wristband, exchanging the authorization code for an access token
    /// and retrieving the user information necessary to complete the login.
    /// </summary>
    /// <param name="context">The HTTP context for the request, containing the authorization code and other parameters.</param>
    /// <returns>A task representing the asynchronous operation, containing the result of the callback execution.</returns>
    /// <exception cref="Exception">Thrown if an error occurs during the callback handling.</exception>
    Task<CallbackResult> Callback(HttpContext context);

    /// <summary>
    /// Generates the URL for logging out of Wristband and revokes the user's refresh token (if provided in the logout config).
    /// </summary>
    /// <param name="context">The HTTP context for the request, containing details about the logout request.</param>
    /// <param name="logoutConfig">Optional configuration specifying how the logout should be handled.</param>
    /// <returns>A task representing the asynchronous operation, containing the logout redirect URL.</returns>
    /// <exception cref="Exception">Thrown if an error occurs during the logout process.</exception>
    Task<string> Logout(HttpContext context, LogoutConfig? logoutConfig);

    /// <summary>
    /// Checks if the user's access token is expired and refreshed the token, if necessary.
    /// </summary>
    /// <param name="refreshToken">The refresh token to use if the access token is expired.</param>
    /// <param name="expiresAt">Unix timestamp in milliseconds at which the access token expires.</param>
    /// <returns>A task representing the asynchronous operation, containing the new token data if refreshed, or null if not.</returns>
    /// <exception cref="Exception">Thrown if an error occurs during the token refresh process.</exception>
    Task<TokenData?> RefreshTokenIfExpired(string refreshToken, long expiresAt);
}
