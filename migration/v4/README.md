<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instructions from version 3.x to version 4.x
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Migration Instructions from Version 3.x to Version 4.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 4.x

<br>

## Table of Contents

- [Overview of Changes](#overview-of-changes)
- [Breaking Changes](#breaking-changes)
  - [.NET Version Requirements](#net-version-requirements)
  - [Query Parameter and URL Placeholder Naming Changes](#query-parameter-and-url-placeholder-naming-changes)
  - [CallbackResult Structure Changes](#callbackresult-structure-changes)
  - [Session Management Overhaul](#session-management-overhaul)
  - [Cookie Configuration Changes](#cookie-configuration-changes)
  - [Authorization Setup Changes](#authorization-setup-changes)
  - [Session Endpoint Changes](#session-endpoint-changes)
  - [Typed Userinfo](#typed-userinfo)
- [Recommended Updates](#recommended-updates)
  - [Token Endpoint](#token-endpoint)

<br>

---

<br>

## Overview of Changes

Version 4.0 is a major release that:

- ✅ Replaces manual session management with SDK-provided session extension methods
- ✅ Replaces the custom `AuthMiddleware` and `RequireWristbandAuth` attribute with built-in authorization policies
- ✅ Introduces `UseWristbandSessionMiddleware()` for automatic session persistence
- ✅ Changes query parameter and URL placeholder naming for consistency (`tenant_domain` → `tenant_name`)
- ✅ Updates `CallbackResult` enum values to PascalCase and adds a `Reason` field for redirect cases
- ✅ Replaces manual cookie configuration with `UseWristbandSessionConfig()`
- ✅ Introduces typed `UserInfo` in place of raw JSON userinfo

<br>

## Breaking Changes

### .NET Version Requirements

v4.x drops support for .NET 6 and .NET 7. You must be running .NET 8 or later.

<br>

### Query Parameter and URL Placeholder Naming Changes

To improve consistency across the SDK, query parameter names and URL placeholders have changed from `tenant_domain` to `tenant_name`. The `LoginConfig` and `LogoutConfig` field names and the `CallbackData` field name have also changed accordingly.

#### Login Endpoint Query Parameters

**v3.x:**
```sh
- GET https://yourapp.io/auth/login?tenant_domain=customer01
```

**v4.x:**
```sh
+ GET https://yourapp.io/auth/login?tenant_name=customer01
```

#### Logout Endpoint Query Parameters

**v3.x:**
```sh
- GET https://yourapp.io/auth/logout?tenant_domain=customer01
```

**v4.x:**
```sh
+ GET https://yourapp.io/auth/logout?tenant_name=customer01
```

> **💡 Note:** The `tenant_custom_domain` query parameter name remains unchanged in both versions.

#### URL Placeholder Changes

**v3.x:**
```csharp
builder.Services.AddWristbandAuth(options =>
{
-   options.LoginUrl = "https://{tenant_domain}.yourapp.com/auth/login";
-   options.RedirectUri = "https://{tenant_domain}.yourapp.com/auth/callback";
    // ...
});
```

**v4.x:**
```csharp
builder.Services.AddWristbandAuth(options =>
{
+   options.LoginUrl = "https://{tenant_name}.yourapp.com/auth/login";
+   options.RedirectUri = "https://{tenant_name}.yourapp.com/auth/callback";
    // ...
});
```

> **⚠️ Important:**
>
> The old `{tenant_domain}` placeholder still works for backwards compatibility, but it is now deprecated and will be removed in a future major version. All new code should use `{tenant_name}`.

#### LoginConfig Field Changes

**v3.x:**
```csharp
- var loginConfig = new LoginConfig
- {
-     DefaultTenantDomainName = "global"
- };
```

**v4.x:**
```csharp
+ var loginConfig = new LoginConfig
+ {
+     DefaultTenantName = "global"
+ };
```

#### LogoutConfig Field Changes

**v3.x:**
```csharp
- var logoutConfig = new LogoutConfig
- {
-     RefreshToken = "98yht308hf902hc90wh09",
-     TenantDomainName = "customer01"
- };
```

**v4.x:**
```csharp
+ var logoutConfig = new LogoutConfig
+ {
+     RefreshToken = "98yht308hf902hc90wh09",
+     TenantName = "customer01"
+ };
```

#### CallbackData Field Changes

The `TenantDomainName` field on `CallbackData` has been renamed to `TenantName`.

**v3.x:**
```csharp
- var tenantDomain = callbackResult.CallbackData.TenantDomainName;
```

**v4.x:**
```csharp
+ var tenantName = callbackResult.CallbackData.TenantName;
```

<br>

### CallbackResult Structure Changes

The `CallbackResult` model in v4.x changes the `CallbackResultType` enum values to PascalCase and adds a new `Reason` field for redirect cases.

#### CallbackResultType Enum Values

The enum values have changed from screaming snake case to PascalCase.

**v3.x:**
```csharp
- if (callbackResult.Type == CallbackResultType.REDIRECT_REQUIRED)
- {
-     return Results.Redirect(callbackResult.RedirectUrl);
- }
```

**v4.x:**
```csharp
+ if (callbackResult.Type == CallbackResultType.RedirectRequired)
+ {
+     return Results.Redirect(callbackResult.RedirectUrl);
+ }
```

The `COMPLETED` value has similarly changed to `Completed`.

#### New `Reason` Field

v4.x adds a `Reason` field to `CallbackResult` that indicates why a redirect is required:

```csharp
if (callbackResult.Type == CallbackResultType.RedirectRequired)
{
    // You can now inspect why redirect is needed
    Console.WriteLine($"Redirect reason: {callbackResult.Reason}");
    // Possible values: MissingLoginState, InvalidLoginState,
    //                  LoginRequired, InvalidGrant
}
```

<br>

### Session Management Overhaul

This is the largest breaking change in v4.x. The SDK now provides built-in session extension methods, a session middleware, and authorization policies. The manual `SignInAsync`/`SignOutAsync` pattern and the custom `AuthMiddleware` are no longer needed.

#### Callback Endpoint — Session Creation

In v3.x, you manually extracted claims from raw userinfo JSON and called `SignInAsync` directly. In v4.x, call `CreateSessionFromCallback()` and the SDK populates all base session fields for you.

**v3.x:**
```csharp
- var userinfo = callbackResult.CallbackData.Userinfo;
- var claims = new List<Claim>
- {
-     new("isAuthenticated", "true"),
-     new("accessToken", callbackResult.CallbackData.AccessToken),
-     new("refreshToken", callbackResult.CallbackData.RefreshToken ?? string.Empty),
-     new("expiresAt", callbackResult.CallbackData.ExpiresAt),
-     new("tenantDomainName", callbackResult.CallbackData.TenantDomainName),
-     new("tenantCustomDomain", callbackResult.CallbackData.TenantCustomDomain ?? string.Empty),
-     new("userId", userinfo.TryGetValue("sub", out var userId) ? userId.GetString() : string.Empty),
-     new("tenantId", userinfo.TryGetValue("tnt_id", out var tenantId) ? tenantId.GetString() : string.Empty),
- };
-
- await httpContext.SignInAsync(
-     CookieAuthenticationDefaults.AuthenticationScheme,
-     new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
-     new AuthenticationProperties { IsPersistent = true });
```

**v4.x:**
```csharp
+ // Basic usage — SDK populates all base session fields automatically
+ httpContext.CreateSessionFromCallback(callbackResult.CallbackData!);

+ // With custom claims (optional)
+ httpContext.CreateSessionFromCallback(
+     callbackResult.CallbackData,
+     customClaims: new[]
+     {
+         new Claim("email", callbackResult.CallbackData.Userinfo.Email ?? ""),
+         new Claim("roles", JsonSerializer.Serialize(callbackResult.CallbackData.Userinfo.Roles))
+     }
+ );
```

#### Logout Endpoint — Session Destruction

In v3.x, you called `SignOutAsync` directly and read claims manually using `FindFirst`. In v4.x, use `DestroySession()` and the SDK's typed session getters.

**v3.x:**
```csharp
- var refreshToken = httpContext.User.FindFirst("refreshToken")?.Value ?? string.Empty;
- var tenantCustomDomain = httpContext.User.FindFirst("tenantCustomDomain")?.Value ?? string.Empty;
- var tenantDomainName = httpContext.User.FindFirst("tenantDomainName")?.Value ?? string.Empty;
-
- await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
-
- var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, new LogoutConfig
- {
-     RefreshToken = refreshToken,
-     TenantCustomDomain = tenantCustomDomain,
-     TenantDomainName = tenantDomainName,
- });
```

**v4.x:**
```csharp
+ var logoutConfig = new LogoutConfig
+ {
+     RefreshToken = httpContext.GetRefreshToken(),
+     TenantCustomDomain = httpContext.GetTenantCustomDomain(),
+     TenantName = httpContext.GetTenantName(),
+ };
+
+ httpContext.DestroySession();
+
+ var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

#### Removing the Custom AuthMiddleware

In v3.x, you wrote a custom `AuthMiddleware` class that checked for the `RequireWristbandAuth` attribute, validated authentication, and handled token refresh with manual `SignInAsync` calls. All of this is now handled by the SDK's built-in authorization handler. Delete your `AuthMiddleware` class entirely, and remove its registration from `Program.cs`:

**v3.x:**
```csharp
- // Program.cs
- app.UseAuthentication();
- app.UseMiddleware<AuthMiddleware>();
```

**v4.x:**
```csharp
+ // Program.cs
+ app.UseAuthentication();
+ app.UseAuthorization();
+ app.UseWristbandSessionMiddleware();
```

#### Replacing RequireWristbandAuth with RequireWristbandSession

The `RequireWristbandAuth` attribute is replaced by the `RequireWristbandSession()` extension method on route builders.

**v3.x:**
```csharp
- app.MapGet("/protected", (HttpContext httpContext) =>
- {
-     return Results.Ok(new { Message = "Protected." });
- })
- .WithMetadata(new RequireWristbandAuth());
```

**v4.x:**
```csharp
+ app.MapGet("/protected", (HttpContext httpContext) =>
+ {
+     return Results.Ok(new { Message = "Protected." });
+ })
+ .RequireWristbandSession();
```

<br>

### Cookie Configuration Changes

In v3.x, you configured every cookie option manually and called `UseWristbandApiStatusCodes()` for API-friendly error responses. In v4.x, `UseWristbandSessionConfig()` applies all recommended defaults in one call, including the API status code behavior. `UseWristbandApiStatusCodes()` no longer exists.

**v3.x:**
```csharp
- builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
-     .AddCookie(options =>
-     {
-         options.Cookie.Name = "session";
-         options.Cookie.HttpOnly = true;
-         options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
-         options.Cookie.SameSite = SameSiteMode.Strict;
-         options.SlidingExpiration = true;
-         options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
-         options.UseWristbandApiStatusCodes();
-     });
```

**v4.x:**
```csharp
+ builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
+     .AddCookie(options => options.UseWristbandSessionConfig());
```

You can still override individual defaults after applying `UseWristbandSessionConfig()`:

```csharp
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.UseWristbandSessionConfig();                        // Apply defaults
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);          // Override expiration
        options.Cookie.Name = "my_session";                         // Override cookie name
    });
```

> **💡 Note:** The default `SameSite` policy has changed from `Strict` (v3.x) to `Lax` (v4.x). `Lax` provides cross-site protection for most scenarios while allowing top-level navigations (e.g., clicking a link from an email). If your application requires `Strict`, override it after calling `UseWristbandSessionConfig()`.

<br>

### Authorization Setup Changes

v4.x requires two new service registrations that did not exist in v3.x: `AddWristbandAuthorizationHandler()` and `AddWristbandDefaultPolicies()`. These must be called before `Build()`. `UseAuthorization()` middleware is also now required and must be called before `UseWristbandSessionMiddleware()`.

**v3.x:**
```csharp
- builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
-     .AddCookie(options => { /* ... */ });
-
- var app = builder.Build();
-
- app.UseAuthentication();
- app.UseMiddleware<AuthMiddleware>();
```

**v4.x:**
```csharp
+ builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
+     .AddCookie(options => options.UseWristbandSessionConfig());
+
+ builder.Services.AddWristbandAuthorizationHandler();
+ builder.Services.AddAuthorization(options => options.AddWristbandDefaultPolicies());
+
+ var app = builder.Build();
+
+ app.UseAuthentication();
+ app.UseAuthorization();
+ app.UseWristbandSessionMiddleware();
```

> **⚠️ Middleware Order Matters:**
>
> Always call `UseAuthentication()` before `UseAuthorization()`, and both before `UseWristbandSessionMiddleware()`.

<br>

### Session Endpoint Changes

In v3.x, you manually constructed the session response from raw claims. In v4.x, use `GetSessionResponse()`, which also automatically sets `Cache-Control: no-store` and `Pragma: no-cache` headers.

**v3.x:**
```csharp
- app.MapGet("/session", (HttpContext httpContext) =>
- {
-     var user = httpContext.User;
-     return Results.Ok(new
-     {
-         userId = user.FindFirst("userId")?.Value ?? string.Empty,
-         tenantId = user.FindFirst("tenantId")?.Value ?? string.Empty,
-         metadata = new
-         {
-             email = user.FindFirst("email")?.Value ?? string.Empty,
-         }
-     });
- })
- .WithMetadata(new RequireWristbandAuth());
```

**v4.x:**
```csharp
+ app.MapGet("/session", (HttpContext httpContext) =>
+ {
+     var response = httpContext.GetSessionResponse(metadata: new
+     {
+         email = httpContext.GetSessionClaim("email"),
+     });
+     return Results.Ok(response);
+ })
+ .RequireWristbandSession();
```

<br>

### Typed Userinfo

In v3.x, `CallbackData.Userinfo` was a raw JSON dictionary that you accessed via `TryGetValue` and manually parsed. In v4.x, it is a typed `UserInfo` object with named properties.

**v3.x:**
```csharp
- var userinfo = callbackResult.CallbackData.Userinfo;
- var userId = userinfo.TryGetValue("sub", out var sub) ? sub.GetString() : string.Empty;
- var tenantId = userinfo.TryGetValue("tnt_id", out var tnt) ? tnt.GetString() : string.Empty;
- var email = userinfo.TryGetValue("email", out var em) ? em.GetString() : string.Empty;
```

**v4.x:**
```csharp
+ var userinfo = callbackResult.CallbackData.Userinfo;
+ var userId = userinfo.UserId;
+ var tenantId = userinfo.TenantId;
+ var email = userinfo.Email;
```

See the [Callback() documentation](../../README.md#callback) for the full list of typed `UserInfo` fields.

<br>

## Recommended Updates

### Token Endpoint

v4.x introduces a new Token Endpoint pattern for frontends that need direct access to the user's access token. While not required, it is recommended if your frontend makes authenticated API calls directly to Wristband or other protected services.

```csharp
app.MapGet("/auth/token", (HttpContext httpContext) =>
{
    var response = httpContext.GetTokenResponse();
    return Results.Ok(response);
})
.RequireWristbandSession();
```

`GetTokenResponse()` automatically sets `Cache-Control: no-store` and `Pragma: no-cache` headers. See the [Token Endpoint documentation](../../README.md#token-endpoint-optional) for more details.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
