using System.Text.Json;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Raw userinfo response from Wristband's OIDC userinfo endpoint.
/// Contains required OIDC claims that are always present, plus optional
/// scope-dependent claims and custom claims.
/// </summary>
/// <remarks>
/// Refer to the Wristband userinfo endpoint documentation to see the full list of
/// possible claims that can be returned, depending on your scopes.
/// </remarks>
internal class RawUserInfo
{
    private JsonElement _data;

    /// <summary>
    /// Initializes a new instance of the <see cref="RawUserInfo"/> class using the provided JSON string.
    /// </summary>
    /// <param name="jsonString">A JSON string representing user information.</param>
    /// <exception cref="ArgumentException">Thrown when the JSON string is null or empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown if deserialization fails or the JSON format is invalid.</exception>
    public RawUserInfo(string jsonString)
    {
        if (string.IsNullOrWhiteSpace(jsonString))
        {
            throw new ArgumentException("JSON string cannot be null or empty.");
        }

        try
        {
            var jsonData = JsonSerializer.Deserialize<JsonElement>(jsonString);
            if (jsonData.ValueKind == JsonValueKind.Undefined)
            {
                throw new InvalidOperationException("Failed to deserialize JSON for Userinfo.");
            }

            _data = jsonData;
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Invalid JSON format for Userinfo.", ex);
        }
    }

    /// <summary>
    /// Retrieves the value associated with the specified claim from the user data.
    /// </summary>
    /// <param name="key">The key for the value to retrieve.</param>
    /// <returns>The value associated with the key.</returns>
    /// <exception cref="KeyNotFoundException">Thrown if the key does not exist.</exception>
    public JsonElement GetValue(string key)
    {
        // This throws an exception if the key doesn't exist
        return _data.GetProperty(key);
    }

    /// <summary>
    /// Attempts to retrieve the value associated with the specified claim from the user data.
    /// </summary>
    /// <param name="key">The key for the value to retrieve.</param>
    /// <param name="value">The value associated with the key if found, otherwise default(JsonElement).</param>
    /// <returns>True if the key was found, otherwise false.</returns>
    public bool TryGetValue(string key, out JsonElement value)
    {
        // Avoids throwing exceptions if the key is missing
        return _data.TryGetProperty(key, out value);
    }
}
