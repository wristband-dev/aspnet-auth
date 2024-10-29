namespace Wristband;

public class AuthConfig {
    public string ClientId { get; set; }
    public string ClientIdForManagingUserMetadata { get; set; }
    public string ClientSecret { get; set; }
    public string ClientSecretForManagingUserMetadata { get; set; }
    public string CustomApplicationLoginPageUrl { get; set; }
    public bool DangerouslyDisableSecureCookies { get; set; }
    public string LoginStateSecret { get; set; }
    public string LoginUrl { get; set; }
    public string RedirectUri { get; set; }
    public string RootDomain { get; set; }
    public List<string> Scopes { get; set; } = new List<string>();
    public bool UseCustomDomains { get; set; }
    public bool UseTenantSubdomains { get; set; }
    public string WristbandApplicationDomain { get; set; }
    public string WristbandTenantDomain { get; set; }
}

public class CallbackData : TokenData {
    public Dictionary<string, object> CustomState { get; set; }
    public UserInfo? Userinfo { get; set; }
}

public class LoginConfig {
    public string DefaultTenantDomain { get; set; }
    public string PostLoginRedirectUrl { get; set; }
}

public class LogoutConfig {
    public string RedirectUrl { get; set; }
}

public class TokenData {
    public string AccessToken { get; set; }
    public int ExpiresIn { get; set; }
    public string IdToken { get; set; }
    public string RefreshToken { get; set; }
}

public class UserInfo : Dictionary<string, object> {}

public class WristbandError : Exception {
    public string Error { get; }
    public string ErrorDescription { get; }

    public WristbandError(string error, string? errorDescription = null) : base(error) {
        Error = error;
        ErrorDescription = errorDescription ?? "";
    }
}