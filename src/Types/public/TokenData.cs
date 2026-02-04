namespace Wristband.AspNet.Auth;

/// <summary>
/// Represents the token data received after authentication.
/// </summary>
public class TokenData
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TokenData"/> class with the specified token data.
    /// </summary>
    /// <param name="accessToken">The access token.</param>
    /// <param name="expiresAt">The absolute expiration time of the access token in milliseconds since the Unix epoch.</param>
    /// <param name="expiresIn">The duration from the current time until the access token expires (in seconds).</param>
    /// <param name="idToken">The ID token.</param>
    /// <param name="refreshToken">The refresh token (optional).</param>
    /// <exception cref="InvalidOperationException">Thrown if any required field is null, empty, or invalid.</exception>
    public TokenData(string accessToken, long expiresAt, int expiresIn, string idToken, string? refreshToken)
    {
        if (string.IsNullOrEmpty(accessToken))
        {
            throw new InvalidOperationException("[AccessToken] cannot be null or empty.");
        }

        if (expiresAt < 0)
        {
            throw new InvalidOperationException("[ExpiresAt] must be a non-negative integer.");
        }

        if (expiresIn < 0)
        {
            throw new InvalidOperationException("[ExpiresIn] must be a non-negative integer.");
        }

        if (string.IsNullOrEmpty(idToken))
        {
            throw new InvalidOperationException("[IdToken] cannot be null or empty.");
        }

        AccessToken = accessToken;
        ExpiresAt = expiresAt;
        ExpiresIn = expiresIn;
        IdToken = idToken;
        RefreshToken = refreshToken;
    }

    /// <summary>
    /// Gets the access token.
    /// </summary>
    public string AccessToken { get; }

    /// <summary>
    /// Gets the absolute expiration time of the access token in milliseconds since the Unix epoch.
    /// </summary>
    public long ExpiresAt { get; }

    /// <summary>
    /// Gets the expiration time of the access token (in seconds).
    /// </summary>
    public int ExpiresIn { get; }

    /// <summary>
    /// Gets the ID token.
    /// </summary>
    public string IdToken { get; }

    /// <summary>
    /// Gets the refresh token (optional).
    /// </summary>
    public string? RefreshToken { get; }
}
