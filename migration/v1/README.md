<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v0.x to version v1.0.0
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

# Migration instruction from version v0.x to version v1.0.0

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 1.x

<br>

## Table of Contents

- [SDK Configuration Property Name Change](#sdk-configuration-property-name-change)
- [Callback Result Property Renaming](#callback-result-property-renamed)

<br>

## SDK Configuration Property Name Change

When calling `AddWristbandAuth()` to initialize the SDK, the `WristbandApplicationDomain` property has been renamed to `WristbandApplicationVanityDomain` in order to be more explicit:

```csharp
// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddWristbandAuth(options =>
{
  // New name for app vanity domain
  - options.WristbandApplicationDomain = "auth.yourapp.io";
  + options.WristbandApplicationVanityDomain = "auth.yourapp.io";
  // Other properties...
});

...
```

<br>

## Callback Result Property Renaming

For the `CallbackResult` that is returned from calling `Callback()`, the `Result` property has been renamed to `Type` in order to reduce confusion:

```csharp
// AuthRoutes.cs
using Wristband.AspNet.Auth;

public static class AuthRoutes
{
    public static WebApplication MapAuthEndpoints(this WebApplication app)
    {
        app.MapGet("/auth/callback", async (HttpContext httpContext, IWristbandAuthService wristbandAuth) =>
        {
            var callbackResult = await wristbandAuth.Callback(httpContext);

            - if (callbackResult.Result == CallbackResultType.REDIRECT_REQUIRED)
            + if (callbackResult.Type == CallbackResultType.REDIRECT_REQUIRED)
            {
                return Results.Redirect(callbackResult.RedirectUrl);
            }
            ...
        });

        ...
    }
}
...

```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
