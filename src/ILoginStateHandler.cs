using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Utility interface for managing state between the login and callback endpoints.
/// </summary>
internal interface ILoginStateHandler
{
    /// <summary>
    /// Creates the <see cref="LoginState"/> that will get stored in a cookie for processing during callback.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the request, containing details about the login request.</param>
    /// <param name="redirectUri">The redirect URI for callback after authentication.</param>
    /// <param name="customState">Custom state data for the login request.</param>
    /// <returns> A <see cref="LoginState"/> for the current login request.</returns>
    LoginState CreateLoginState(HttpContext httpContext, string redirectUri, Dictionary<string, object>? customState);

    /// <summary>
    /// Sets a response cookie containing the login state to be preserved until the time of callback processing.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the request, containing details about the login request.</param>
    /// <param name="loginState">Represents all possible state information for the current login request, which is stored in the login state cookie.</param>
    /// <param name="loginStateSecret">A secret (32 or more characters in length) used for encryption and decryption of login state cookies.</param>
    /// <param name="dangerouslyDisableSecureCookies">If set to true, the "Secure" attribute will not be included in any cookie settings. Should be used only in local development.</param>
    void CreateLoginStateCookie(HttpContext httpContext, LoginState loginState, string loginStateSecret, bool dangerouslyDisableSecureCookies);

    /// <summary>
    /// Attempts to fetch and clear the login state cookie for the current login request.
    /// </summary>
    /// <param name="httpContext">The HTTP context for the request, containing details about the login request.</param>
    /// <param name="dangerouslyDisableSecureCookies">If set to true, the "Secure" attribute will not be included in any cookie settings. Should be used only in local development.</param>
    /// <returns>The login state cookie, if found. Otherwise, and empty string.</returns>
    string GetAndClearLoginStateCookie(HttpContext httpContext, bool dangerouslyDisableSecureCookies);

    /// <summary>
    /// Decrypts the encrypted value of the login state cookie that was created for the current login request.
    /// </summary>
    /// <param name="encryptedState">The string representing the encrypted login state cookie.</param>
    /// <param name="loginStateSecret">A secret (32 or more characters in length) used for encryption and decryption of login state cookies.</param>
    /// <returns> A <see cref="LoginState"/> for the current login request.</returns>
    LoginState DecryptLoginState(string encryptedState, string loginStateSecret);

    /// <summary>
    /// Create a random, base64-encoded string.
    /// </summary>
    /// <param name="length">The desired length of the generated string.</param>
    /// <returns>The random string.</returns>
    string GenerateRandomString(int length);
}
