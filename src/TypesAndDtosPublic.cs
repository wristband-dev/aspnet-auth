using System;
using System.Text.Json;

namespace Wristband.AspNet.Auth;

// ////////////////////////////////////
//  MAIN SDK CONFIGURATION
// ////////////////////////////////////

public class AuthConfig
{
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? CustomApplicationLoginPageUrl { get; set; }
    public bool? DangerouslyDisableSecureCookies { get; set; } = false;
    public string? LoginStateSecret { get; set; }
    public string? LoginUrl { get; set; }
    public string? RedirectUri { get; set; }
    public string? RootDomain { get; set; }
    public List<string>? Scopes { get; set; } = new List<string>();
    public bool? UseCustomDomains { get; set; } = false;
    public bool? UseTenantSubdomains { get; set; } = false;
    public string? WristbandApplicationDomain { get; set; }

    public AuthConfig() { }

    public AuthConfig(
        string? clientId,
        string? clientSecret,
        string? loginStateSecret,
        string? loginUrl,
        string? redirectUri,
        string? wristbandApplicationDomain,
        string? customApplicationLoginPageUrl,
        bool? dangerouslyDisableSecureCookies,
        string? rootDomain,
        List<string>? scopes,
        bool? useCustomDomains,
        bool? useTenantSubdomains)
    {
        ClientId = clientId;
        ClientSecret = clientSecret;
        LoginStateSecret = loginStateSecret;
        LoginUrl = loginUrl;
        RedirectUri = redirectUri;
        WristbandApplicationDomain = wristbandApplicationDomain;
        CustomApplicationLoginPageUrl = customApplicationLoginPageUrl;
        DangerouslyDisableSecureCookies = dangerouslyDisableSecureCookies;
        RootDomain = rootDomain;
        Scopes = scopes;
        UseCustomDomains = useCustomDomains;
        UseTenantSubdomains = useTenantSubdomains;
    }
}

// ////////////////////////////////////
//  LOGIN TYPES
// ////////////////////////////////////

public class LoginConfig
{
    public Dictionary<string, object>? CustomState { get; set; }
    public string? DefaultTenantCustomDomain { get; set; }
    public string? DefaultTenantDomainName { get; set; }

    public LoginConfig() { }

    public LoginConfig(Dictionary<string, object>? customState, string? defaultTenantCustomDomain, string? defaultTenantDomainName)
    {
        CustomState = customState;
        DefaultTenantCustomDomain = defaultTenantCustomDomain;
        DefaultTenantDomainName = defaultTenantDomainName;
    }
}

// ////////////////////////////////////
//  CALLBACK TYPES
// ////////////////////////////////////

public class TokenData
{
    public string AccessToken { get; }
    public int ExpiresIn { get; }
    public string IdToken { get; }
    public string? RefreshToken { get; }

    public TokenData(string accessToken, int expiresIn, string idToken, string? refreshToken)
    {
        if (string.IsNullOrEmpty(accessToken))
        {
            throw new InvalidOperationException("[AccessToken] cannot be null or empty.");
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
        ExpiresIn = expiresIn;
        IdToken = idToken;
        RefreshToken = refreshToken;
    }
}

public class CallbackData : TokenData
{
    public static readonly CallbackData Empty = new CallbackData(
        accessToken: "empty",
        expiresIn: 0,
        idToken: "empty",
        refreshToken: null,
        userinfo: UserInfo.Empty,
        tenantDomainName: "empty",
        tenantCustomDomain: null,
        customState: null,
        returnUrl: null
    );

    public Dictionary<string, object>? CustomState { get; }
    public UserInfo Userinfo { get; }
    public string? ReturnUrl { get; }
    public string TenantDomainName { get; }
    public string? TenantCustomDomain { get; }

    public CallbackData(
        string accessToken,
        int expiresIn,
        string idToken,
        string? refreshToken,
        UserInfo userinfo,
        string tenantDomainName,
        string? tenantCustomDomain,
        Dictionary<string, object>? customState,
        string? returnUrl
    ) : base(accessToken, expiresIn, idToken, refreshToken)
    {
        if (userinfo == null)
        {
            throw new InvalidOperationException("[Userinfo] cannot be null.");
        }

        if (string.IsNullOrEmpty(tenantDomainName))
        {
            throw new InvalidOperationException("[TenantDomainName] cannot be null or empty.");
        }

        Userinfo = userinfo;
        TenantDomainName = tenantDomainName;
        TenantCustomDomain = tenantCustomDomain;
        CustomState = customState;
        ReturnUrl = returnUrl;
    }
}

public class UserInfo
{
    public static readonly UserInfo Empty = new UserInfo("{}");

    private JsonElement _data;

    public UserInfo(string jsonString)
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

    public JsonElement GetValue(string key)
    {
        // This throws an exception if the key doesn't exist
        return _data.GetProperty(key);
    }

    public bool TryGetValue(string key, out JsonElement value)
    {
        // Avoids throwing exceptions if the key is missing
        return _data.TryGetProperty(key, out value);
    }
}

public enum CallbackResultType
{
    COMPLETED,
    REDIRECT_REQUIRED,
}

public class CallbackResult
{
    public CallbackData CallbackData { get; }
    public string RedirectUrl { get; }
    public CallbackResultType Result { get; }

    public CallbackResult(CallbackResultType result, CallbackData? callbackData, string? redirectUrl)
    {
        if (result == CallbackResultType.COMPLETED && callbackData == null)
        {
            throw new ArgumentNullException(nameof(callbackData), "CallbackData cannot be null for COMPLETED result.");
        }

        if (result == CallbackResultType.REDIRECT_REQUIRED && string.IsNullOrEmpty(redirectUrl))
        {
            throw new ArgumentNullException(nameof(redirectUrl), "RedirectUrl cannot be null for REDIRECT_REQUIRED result.");
        }

        Result = result;
        CallbackData = callbackData ?? CallbackData.Empty;
        RedirectUrl = redirectUrl ?? string.Empty;
    }
}

// ////////////////////////////////////
//  LOGOUT TYPES
// ////////////////////////////////////

public class LogoutConfig
{
    public string? RedirectUrl { get; set; }
    public string? RefreshToken { get; set; }
    public string? TenantCustomDomain { get; set; }
    public string? TenantDomainName { get; set; }

    public LogoutConfig() { }

    public LogoutConfig(string? redirectUrl, string? refreshToken, string? tenantCustomDomain, string? tenantDomainName)
    {
        RedirectUrl = redirectUrl;
        RefreshToken = refreshToken;
        TenantCustomDomain = tenantCustomDomain;
        TenantDomainName = tenantDomainName;
    }
}

// ////////////////////////////////////
//  ERROR TYPES
// ////////////////////////////////////

public class WristbandError : Exception
{
    public string Error { get; }
    public string ErrorDescription { get; }

    public WristbandError(string error, string? errorDescription) : base(error)
    {
        Error = error;
        ErrorDescription = errorDescription ?? string.Empty;
    }
}
