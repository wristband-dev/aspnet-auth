<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instructions from version 4.x to version 5.x
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

# Migration Instructions from Version 4.x to Version 5.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 5.x

<br>

## Table of Contents

- [Application-Level Authorization Requests Enabled by Default](#application-level-authorization-requests-enabled-by-default)
- [Tenant Domain URL Placeholder Removed](#tenant-domain-url-placeholder-removed)
- [ParseTenantFromRootDomain Config Removed](#parsetenantfromrootdomain-config-removed)
- [Return URL Validation in Callback()](#return-url-validation-in-callback)
- [Login State Cookie Changes](#login-state-cookie-changes)

<br>

## Application-Level Authorization Requests Enabled by Default

The SDK now supports Application-Level Authorization Requests through the `ApplicationAuthorizationRequestsEnabled` config. It is auto-configured from your Application's settings in the Wristband Dashboard, and it defaults to `true`. This lets third-party platforms and SDKs that require a single, static Authorization Endpoint URL (e.g. Supabase) use one fixed URL in addition to per-tenant URLs.

This only changes behavior when `Login()` or `Logout()` cannot resolve a tenant from the request (no tenant subdomain, `tenant_name` or `tenant_custom_domain` query parameter, or default tenant):

- `Login()` returns the Wristband Authorize Endpoint URL on your application's vanity domain, and Wristband handles tenant discovery within that same authorization flow. The return URL is preserved in the Login State Cookie. In 4.x, `Login()` returned the Application-Level Login (Tenant Discovery) Page URL.
- `Logout()`, when no `RedirectUrl` is set in `LogoutConfig`, returns your application's own Login Endpoint to start a new app-level flow. That is your `LoginUrl` with the `{tenant_name}` subdomain removed if it contains the placeholder, or your `LoginUrl` as is otherwise.
- `CustomApplicationLoginPageUrl` has no effect on `Login()` or `Logout()`.
- When `LoginUrl` contains the `{tenant_name}` placeholder, the Login State Cookie is set on your root domain (e.g. `.yourapp.io`) in both the app-level and tenant-level login flows, and `Callback()` clears it with the same domain.

To keep the 4.x behavior, turn the setting off on your Application's Settings page in the Wristband Dashboard, or set it in your SDK config:

```csharp
builder.Services.AddWristbandAuth(options =>
{
    // ... other config
+   options.ApplicationAuthorizationRequestsEnabled = false;
});
```

<br>

## Tenant Domain URL Placeholder Removed

The `{tenant_domain}` placeholder has been removed. `{tenant_name}` is now the only supported tenant placeholder in `LoginUrl` and `RedirectUri`.

**Before (4.x):**
```csharp
builder.Services.AddWristbandAuth(options =>
{
    // ... other config
-   options.LoginUrl = "https://{tenant_domain}.yourapp.com/auth/login";
-   options.RedirectUri = "https://{tenant_domain}.yourapp.com/auth/callback";
});
```

**After (5.x):**
```csharp
builder.Services.AddWristbandAuth(options =>
{
    // ... other config
+   options.LoginUrl = "https://{tenant_name}.yourapp.com/auth/login";
+   options.RedirectUri = "https://{tenant_name}.yourapp.com/auth/callback";
});
```

<br>

## ParseTenantFromRootDomain Config Removed

The `ParseTenantFromRootDomain` config has been removed from `WristbandAuthConfig`, including its parameter in the `WristbandAuthConfig` constructor. Tenant subdomain parsing is now enabled whenever `LoginUrl` contains the `{tenant_name}` placeholder, and the SDK determines the root domain from `LoginUrl` by removing the `{tenant_name}` subdomain.

**Before (4.x):**
```csharp
builder.Services.AddWristbandAuth(options =>
{
    // ... other config
    options.LoginUrl = "https://{tenant_name}.yourapp.com/auth/login";
    options.RedirectUri = "https://{tenant_name}.yourapp.com/auth/callback";
-   options.ParseTenantFromRootDomain = "yourapp.com";
});
```

**After (5.x):**
```csharp
builder.Services.AddWristbandAuth(options =>
{
    // ... other config
    options.LoginUrl = "https://{tenant_name}.yourapp.com/auth/login";
    options.RedirectUri = "https://{tenant_name}.yourapp.com/auth/callback";
});
```

**Key Changes:**
1. Remove `ParseTenantFromRootDomain` from your SDK config, and from `appsettings.json` if you bind it from configuration
2. The root domain is derived from `LoginUrl` (e.g. `https://{tenant_name}.yourapp.com/auth/login` gives a root domain of `yourapp.com`)
3. If your app relies on auto-configuration and never set `ParseTenantFromRootDomain`, no change is needed

> **⚠️ Important:**
>
> The `{tenant_name}` placeholder must appear exactly once in `LoginUrl` and `RedirectUri`, as the leftmost part of the hostname. Either both URLs contain the placeholder or neither does.

<br>

## Return URL Validation in Callback()

`Callback()` now validates the return URL before including it in the returned callback data. In 4.x, the return URL was passed through unchanged. A return URL that fails validation is now left out of the callback data, and the flow continues without it.

**Before (4.x):**
```csharp
// Login request: /auth/login?return_url=https://otherapp.com/dashboard
var callbackResult = await wristbandAuth.Callback(context);

if (callbackResult.Type == CallbackResultType.Completed)
{
    var returnUrl = callbackResult.CallbackData.ReturnUrl;
-   // returnUrl == "https://otherapp.com/dashboard"
-   return Results.Redirect(returnUrl);
}
```

**After (5.x):**
```csharp
// Login request: /auth/login?return_url=https://otherapp.com/dashboard
var callbackResult = await wristbandAuth.Callback(context);

if (callbackResult.Type == CallbackResultType.Completed)
{
    var returnUrl = callbackResult.CallbackData.ReturnUrl;
+   // returnUrl is null (the host does not match the request host or the root domain)
+   return Results.Redirect(returnUrl ?? "/home");
}
```

**Key Changes:**
1. Relative paths (e.g. `/settings`) resolve against the current request's host
2. The scheme must match the request's scheme, which blocks downgrades like `https` to `http` (behind a reverse proxy, use the Forwarded Headers Middleware so that `HttpRequest.Scheme` and `HttpRequest.Host` reflect what the browser used)
3. The hostname must be either the root domain (when `LoginUrl` contains the `{tenant_name}` placeholder) or the request's host
4. When application-level authorization requests are enabled and `LoginUrl` contains the `{tenant_name}` placeholder, a return URL on the bare root domain is rewritten to the tenant's subdomain (e.g. `yourapp.com` to `acme.yourapp.com`)

> **⚠️ Important:**
>
> Make sure your Callback Endpoint has a default redirect location for when `ReturnUrl` is not present, since a return URL that worked in 4.x may now be left out.

<br>

## Login State Cookie Changes

No code or config changes are needed for the following:

1. The Login State Cookie's 1-hour lifetime is now also enforced when decrypting, with a 60-second clock skew tolerance. Login State Cookies created by 4.x don't record when they were created, so a user who is mid-login during the upgrade is redirected to the Login Endpoint once. Because Wristband already has an authenticated session for that user, the new login flow completes without asking them to sign in again.
2. When the Login State Cookie cannot be decrypted (tampered, malformed, or encrypted with a different secret), `Callback()` no longer throws an exception. It returns a `RedirectRequired` result with the `InvalidLoginState` reason.

> **⚠️ Important:**
>
> If your Callback Endpoint already handles the `RedirectRequired` result type, no change is needed.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
