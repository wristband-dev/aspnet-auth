<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.
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

# Wristband Multi-Tenant Authentication SDK for ASP.NET

[![NuGet](https://img.shields.io/nuget/v/Wristband.AspNet.Auth?label=NuGet)](https://www.nuget.org/packages/Wristband.AspNet.Auth/)
[![version number](https://img.shields.io/github/v/release/wristband-dev/aspnet-auth?color=green&label=version)](https://github.com/wristband-dev/aspnet-auth/releases)
[![Actions Status](https://github.com/wristband-dev/aspnet-auth/workflows/Test/badge.svg)](https://github.com/wristband-dev/aspnet-auth/actions)
[![License](https://img.shields.io/github/license/wristband-dev/aspnet-auth)](https://github.com/wristband-dev/aspnet-auth/blob/main/LICENSE)

This module facilitates seamless interaction with Wristband for user authentication within multi-tenant [ASP.NET Core applications](https://dotnet.microsoft.com/en-us/apps/aspnet). It follows OAuth 2.1 and OpenID standards.

Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Auth Flows Walkthrough](https://docs.wristband.dev/docs/auth-flows-and-diagrams)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#1-installation)
- [Wristband Configuration](#2-wristband-configuration)
- [SDK Configuration](#3-sdk-configuration)
  - [Non-Secret Values Configuration](#non-secret-values-configuration)
  - [Secret Values Configuration](#secret-values-configuration)
- [Application Session Configuration](#4-applicaiton-session-configuration)
- [Auth Endpoints](#5-add-auth-endpoints)
  - [Login Endpoint](#login-endpoint)
  - [Callback Endpoint](#callback-endpoint)
  - [Logout Endpoint](#logout-endpoint)
  - [Session Endpoint](#session-endpoint)
- [Guard APIs and Handle Token Refresh](#6-guard-your-non-auth-apis-and-handle-token-refresh)
  - [App Session Middleware](#app-session-middleware)
- [Pass Access Token to Downstream APIs](#7-pass-your-access-token-to-downstream-apis)
- [Wristband Auth Configuration Options](#wristband-auth-configuration-options)
- [API Reference](#api)
  - [Login](#taskstring-loginhttpcontext-context-loginconfig-loginconfig)
  - [Callback](#taskcallbackresult-callbackhttpcontext-context)
  - [Logout](#taskstring-logouthttpcontext-context-logoutconfig-logoutconfig)
  - [RefreshTokenIfExpired](#tasktokendata-refreshtokenifexpiredstring-refreshtoken-long-expiresat)
- [Questions](#questions)

## Requirements

This SDK is supported for .NET 6, .NET 7, .NET 8, and .NET 9.

## 1) Installation

This SDK is available in [Nuget](https://www.nuget.org/organization/wristband) and can be installed with the `dotnet` CLI:
```sh
dotnet add package Wristband.AspNet.Auth
```

Or it can also be installed through the Package Manager Console as well:
```sh
Install-Package Wristband.AspNet.Auth
```

You should see the dependency added to your `.csproj` file:

```xml
<ItemGroup>
  <PackageReference Include="Wristband.AspNet.Auth" Version="0.1.0" />
</ItemGroup>
```


## 2) Wristband Configuration

First, you'll need to make sure you have an Application in your Wristband Dashboard account. If you haven't done so yet, refer to our docs on [Creating an Application](https://docs.wristband.dev/docs/setting-up-your-wristband-account).
- Configure your Wristband Application with your desired Login Url, such as `https://example.com/auth/login` or `https://{tenant_domain}.example.com/auth/login` for subdomain usage.
- **Make sure to copy the Application Vanity Domain for next steps, which can be found in "Application Settings" for your Wristband Application.**

Then, you'll create a [Backend Server](https://docs.wristband.dev/docs/backend-server-integration) OAuth2 Client under that Application while still in the Dashboard.
- During creation, configure your OAuth2 Client with your desired Authorization Callback Url, such as `https://example.com/auth/callback` or `https://{tenant_domain}.example.com/auth/callback` for subdomain usage.
- **Make sure to have your OAuth2 Client's Client Id and Client Secret handy for next steps, which you'll have the opportunity to copy during creation.**

The Application Vanity Domain, Client ID, and Client Secret values are needed to configure your ASP.NET web application.

## 3) SDK Configuration

There are both secret and non-secret values we'll need to set up for the SDK.

### Non-Secret Values Configuration
To enable proper communication between your ASP.NET web application and Wristband, add the following configuration section to your `appsettings.json` file, replacing all placeholder values with your own.

Without subdomains:
```json
"WristbandAuthConfig": {
  "ClientId": "--some-identifier--",
  "LoginUrl": "https://example.com/auth/login",
  "RedirectUri": "https://example.com/auth/callback",
  "Scopes": ["openid", "offline_access", "email", "roles", "profile"],
  "UseTenantSubdomains": "false",
  "WristbandApplicationDomain": "sometest-account.us.wristband.dev"
},
```

Using subdomains:
```json
"WristbandAuthConfig": {
  "ClientId": "--some-identifier--",
  "LoginUrl": "https://{tenant_domain}.example.com/auth/login",
  "RedirectUri": "https://{tenant_domain}.example.com/auth/callback",
  "RootDomain": "example.com",
  "Scopes": ["openid", "offline_access", "email", "roles", "profile"],
  "UseTenantSubdomains": "true",
  "WristbandApplicationDomain": "sometest-parent.us.wristband.dev"
},
```

### Secret Values Configuration
To configure the Client Secret and LoginStateSecret that the SDK relies on in a secure manner during local testing, you can use .NET User Secrets:

1. Initialize user secrets in your project:
```sh
dotnet user-secrets init
```

This will add a "UserSecretsId" to your `.csproj` file that looks like this:
```xml
<PropertyGroup>
  <UserSecretsId>a-randomly-generated-guid</UserSecretsId>
</PropertyGroup>
```


2. Set your secrets using the CLI:
```sh
dotnet user-secrets set "WristbandAuthConfig:ClientSecret" "your-client-secret"
dotnet user-secrets set "WristbandAuthConfig:LoginStateSecret" "your-login-state-secret"
```

Alternatively, you can manage secrets through Visual Studio by right-clicking your project and selecting "Manage User Secrets". Then add the following to secrets.json:
```json
{
  "WristbandAuthConfig": {
    "ClientSecret": "your-client-secret",
    "LoginStateSecret": "your-login-state-secret"
  }
}
```

> [!NOTE]
> Run `openssl rand -base64 32` to create a 32 byte, base-64 encoded secret. LoginStateSecret will be used to secure cookie contents for login requests to Wristband.

3. During development, the secrets will automatically be loaded when you create your WebApplication builder for the following methods:
- A `secrets.json` in development, or,
- Environment variables prefixed with `ASPNETCORE_`
```csharp
var builder = WebApplication.CreateBuilder(args);
```

You can also explicitly load secrets through the User Secrets configuration provider:
```csharp
builder.Configuration.AddUserSecrets<Program>();
```

Or you can explicitly load from a JSON file:
```csharp
builder.Configuration.AddJsonFile("mysecrets.json", optional: true);
```

In production, another alternative to environment variables is a secure configuration management system:
```csharp
builder.Configuration.AddAzureKeyVault(
    new Uri("https://your-vault.vault.azure.net/"),
    new DefaultAzureCredential());
```

> [!NOTE]
> User secrets are for development only. For production, use environment variables or your platform's secure configuration management system.


4. Enable authentication middleware, and add the SDK's WristbandAuthenticationService in your `Program.cs` file. The SDK supports two configuration approaches:

**Via configuration section (recommended for production)...**
```csharp
// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

// Register Wristband authentication configuration and inject WristbandAuthService.
builder.Services.AddWristbandAuth(builder.Configuration);

//
// Other middleware and routes...
//

...
```

**... or via direct configuration (useful for development, testing, or when configuration values need to be computed at runtime):**
```csharp
// Program.cs
builder.Services.AddWristbandAuth(options =>
{
  options.ClientId = "direct-client";
  options.ClientSecret = "direct-secret";
  options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
  options.LoginUrl = "https://login.url";
  options.RedirectUri = "https://redirect.uri";
  options.WristbandApplicationDomain = "wristband.domain";
});
```

## 4) Applicaiton Session Configuration

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies. We recommend using ASP.NET Core's built-in cookie authentication with strict security settings and custom error handling, as shown in the example below:

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Wristband.AspNet.Auth;

...

// Add cookie session for authenticated users
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        // Return 401 errors codes to client instead of redirects.
        options.UseWristbandApiStatusCodes();
    });

var app = builder.Build();

// This middleware must be added before any endpoints that require authentication.
app.UseAuthentication();

...
```

## 5) Add Auth Endpoints

There are <ins>three core API endpoints</ins> your C# server should expose to facilitate both the Login and Logout workflows in Wristband. You'll need to add them to wherever your routes are.

#### [Login Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#login-endpoint)

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```csharp
// auth-routes.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

public static class AuthRoutes
{
    public static WebApplication MapAuthEndpoints(this WebApplication app)
    {
        // Login Endpoint - Route path can be whatever you prefer
        app.MapGet("/auth/login", async (HttpContext httpContext, IWristbandAuthService wristbandAuth) =>
        {
            try {
                // Call the Wristband Login() method and redirect to the resulting URL.
                var wristbandAuthorizeUrl = await wristbandAuth.Login(httpContext, null);
                return Results.Redirect(wristbandAuthorizeUrl);
            } catch (Exception ex) {
                return Results.Problem(detail: $"Unexpected error: {ex.Message}", statusCode: 500);
            }
        })

        //
        // Other auth routes...
        //
    }
}
```

#### [Callback Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#callback-endpoint)

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```csharp
// auth-routes.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

public static class AuthRoutes
{

    ...

    // Callback Endpoint - Route path can be whatever you prefer
    app.MapGet("/auth/callback", async (HttpContext httpContext, IWristbandAuthService wristbandAuth) =>
    {
        try
        {
            // Call the Wristband Callback() method to get results, token data, and user info.
            var callbackResult = await wristbandAuth.Callback(httpContext);

            // For some edge cases, the SDK will require a redirect to restart the login flow.
            if (callbackResult.Result == CallbackResultType.REDIRECT_REQUIRED)
            {
                return Results.Redirect(callbackResult.RedirectUrl);
            }

            // Extract your desired user info.
            var userinfo = callbackData.Userinfo;
            var claims = new List<Claim>
            {
                // Auth-related claims
                new("isAuthenticated", "true"),
                new("accessToken", callbackData.AccessToken),
                new("refreshToken", callbackData.RefreshToken ?? string.Empty),
                // Convert expiration seconds to a Unix timestamp in milliseconds.
                new("expiresAt", $"{DateTimeOffset.Now.ToUnixTimeMilliseconds() + (callbackData.ExpiresIn * 1000)}"),

                // Domain-related claims
                new("tenantDomainName", callbackData.TenantDomainName),
                new("tenantCustomDomain", callbackData.TenantCustomDomain ?? string.Empty),

                // Userinfo-related claims
                new("userId", userinfo.TryGetValue("sub", out var userId) ? userId.GetString() : string.Empty),
                new("tenantId", userinfo.TryGetValue("tnt_id", out var tenantId) ? tenantId.GetString() : string.Empty),
                //
                // Add whatever user info claims your app needs...
                //
            };

            // Create your application session cookie
            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme, 
                    new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                new AuthenticationProperties { IsPersistent = true });

            // For the happy path, send users into your desired app URL!
            var tenantPostLoginRedirectUrl = $"http://{callbackResult.CallbackData.TenantDomainName}.example.com";
            return Results.Redirect(tenantPostLoginRedirectUrl);
        } catch (Exception ex)
        {
            return Results.Problem(detail: $"Unexpected error: {ex.Message}", statusCode: 500);
        }
    })
    //
    // Other auth routes...
    //
};
```

#### [Logout Endpoint](https://docs.wristband.dev/docs/auth-flows-and-diagrams#logout-endpoint-1)

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).


```csharp
// auth-routes.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

public static class AuthRoutes
{

    ...

    // Logout Endpoint - Route path can be whatever you prefer
    app.MapGet("/auth/logout", async (HttpContext httpContext, IWristbandAuthService wristbandAuth) =>
    {
        try
        {
            // Grab necessary session fields for the Logout() function.
            var refreshToken = context.User.FindFirst("refreshToken")?.Value ?? string.Empty;
            var tenantCustomDomain = context.User.FindFirst("tenantCustomDomain")?.Value ?? string.Empty;
            var tenantDomainName = context.User.FindFirst("tenantDomainName")?.Value ?? string.Empty;
      
            // Destroy your application session.
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Call the Wristband Logout() method and redirect to the resulting URL.
            var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, new LogoutConfig
            {
                RefreshToken = refreshToken ?? null,
                TenantCustomDomain = tenantCustomDomain ?? null,
                TenantDomainName = tenantDomainName ?? null,
            });
            return Results.Redirect(wristbandLogoutUrl);
        }
        catch (Exception ex)
        {
            return Results.Problem(detail: $"Unexpected error: {ex.Message}", statusCode: 500);
        }
    });
    //
    // Other auth routes...
    //
}
```

#### [Session Endpoint](https://docs.wristband.dev/docs/session-management-backend-server)

When using a "Backend Server" OAuth2 Client type in Wristband, your client-side Javascript must initialize the user's session by requesting session data from a session endpoint on your C# server. Like any other protected resource API in your server, the user must be already authenticated to access the route. This session endpoint relies on the presence of a session cookie to extract the user's session information.

We'll also need to decorate the route with the `RequireWristbandAuth` attribute so that auth middleware knows to verify autheticated access for incoming requests.

```csharp
// auth-routes.cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

public static class AuthRoutes
{
    ...

    // Session Endpoint - Route path can be whatever you prefer
    app.MapGet("/session", (HttpContext httpContext) =>
    {
        var user = httpContext.User;

        //
        // You can make other API calls to get additional data for return.
        //

        return Results.Ok(new 
        { 
            IsAuthenticated = user.FindFirst("isAuthenticated")?.Value == "true",
            UserId = user.FindFirst("userId")?.Value ?? string.Empty,
            Email = user.FindFirst("email")?.Value ?? string.Empty,
            TenantId = user.FindFirst("tenantId")?.Value ?? string.Empty,
            //
            // Return any user info that your app needs...
            //
        });
    })
    .WithMetadata(new RequireWristbandAuth());
}
```

### 6) Guard Your Non-Auth APIs and Handle Token Refresh

> [!NOTE]
> There may be applications that do not want to utilize access tokens and/or refresh tokens. If that applies to your application, then you can ignore using the `refreshTokenIfExpired()` functionality.

#### App Session Middleware

Create a middleware somewhere in your project to check that your session is still valid. It must check if the access token is expired and perform a token refresh if necessary. The Wristband SDK will make 3 attempts to refresh the token and return the latest JWTs to your server.


```csharp
// auth-middleware.cs
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Wristband.AspNet.Auth;

public class AuthMiddleware
{
    private readonly RequestDelegate _next;
    public AuthMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context, IWristbandAuthService wristbandAuth)
    {
        // Skip authentication for endpoints without the RequireWristbandAuth attribute
        if (context.GetEndpoint()?.Metadata.GetMetadata<RequireWristbandAuthAttribute>() == null)
        {
            await _next(context);
            return;
        }

        // Verify authentication
        if (!await IsAuthenticated(context))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        try
        {
            var refreshToken = context.User.FindFirst("refreshToken")?.Value ?? string.Empty;
            var expiresAt = long.TryParse(context.User.FindFirst("expiresAt")?.Value, out var exp) ? exp : 0;
            var tokenData = await wristbandAuth.RefreshTokenIfExpired(refreshToken, expiresAt);

            // Update token claims if refresh was necessary
            var claims = context.User.Claims;    
            if (tokenData != null)
            {
                claims = claims
                    .Where(c => !new[] { "accessToken", "refreshToken", "expiresAt" }.Contains(c.Type))
                    .Concat(new[]
                    {
                        new Claim("accessToken", tokenData.AccessToken),
                        new Claim("refreshToken", tokenData.RefreshToken ?? string.Empty),
                        new Claim("expiresAt", $"{DateTimeOffset.Now.ToUnixTimeMilliseconds() + (tokenData.ExpiresIn * 1000)}")
                    });
            }

            await context.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)),
                new AuthenticationProperties { IsPersistent = true });
            await _next(context);
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        }
    }

    private async Task<bool> IsAuthenticated(HttpContext context)
    {
        var authResult = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return authResult.Succeeded && 
            authResult.Principal != null && 
            context.User.FindFirst("isAuthenticated")?.Value == "true";
    }
}
```

Now configure your auth middleware in `Program.cs` right before any routes that must be protected with an authenticated session:

```csharp
// Program.cs
...
app.UseAuthentication();
app.UseMiddleware<AuthMiddleware>(); // Place after cookie authentication middleware

// Protected routes below...

```

For any protected routes, you can use the `RequireWristbandAuth` attribute to decorate the route, much like the Session Endpoint.

```csharp
// protected-routes.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

public static class ProtectedRoutes
{
    public static WebApplication MapProtectedRoutes(this WebApplication app)
    {
        app.MapGet("/protected", (HttpContext httpContext) =>
        {
            return Results.Ok(new { Message = "This is a protected route." });
        })
        .WithMetadata(new RequireWristbandAuth());

        return app;
    }
}
```


### 7) Pass Your Access Token to Downstream APIs

> [!NOTE]
> This is only applicable if you wish to call Wristband's APIs directly or protect your application's other downstream backend APIs.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.

```
Authorization: Bearer <access_token_value>
```

You can get the access token from your application session in order to set it on the `Authorization` header as follows:

```csharp
// You could pull this function into a utils file and use it across your project.
private static HttpRequestMessage CreateAuthorizedRequest(HttpMethod method, string url, HttpContext context)
{
    var request = new HttpRequestMessage(method, url);
    var accessToken = context.User.FindFirst("accessToken")?.Value 
        ?? throw new InvalidOperationException("Access token is missing or empty");

    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    return request;
}

// Fictional example usage + pseudocode
app.MapPost("/orders", async (HttpContext context, HttpClient httpClient) =>
{
    try
    {
        var newOrder = await context.Request.ReadFromJsonAsync<Order>();
        await SaveOrderToDatabase(newOrder);

        // Create request with token
        var request = CreateAuthorizedRequest(HttpMethod.Post, "https://api.example.com/email-receipt", context);
        request.Content = JsonContent.Create(newOrder);

        // Send the request
        var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return Results.Ok();
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex);
        return Results.StatusCode(500);
    }
});
```

## Wristband Auth Configuration Options

The `AddWristbandAuth()` extension is used to instatiate the Wristband Auth SDK.  It takes a `WristbandAuthConfig` type as an argument.

```csharp
// Configuration JSON
builder.Services.AddWristbandAuth(builder.Configuration);

// or...

// Direct Configuration
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "direct-client";
    options.ClientSecret = "direct-secret";
    options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
    options.LoginUrl = "https://login.url";
    options.RedirectUri = "https://redirect.uri";
    options.WristbandApplicationDomain = "wristband.domain";
});
```

| AuthConfig Options | Type | Required | Description                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------- | ---- |----|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ClientId | string | Yes | The ID of the Wristband client.                                                                                                                                                                                                                                                                                                                                                       |
| ClientSecret | string | Yes | The client's secret.                                                                                                                                                                                                                                                                                                                                                                                     |
| CustomApplicationLoginPageUrl | string | No | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL.           |
| DangerouslyDisableSecureCookies | boolean | No | USE WITH CAUTION: If set to `true`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `false`.                                                                                                                                          |
| LoginStateSecret | string | Yes | A 32 byte, base64 encoded secret used for encryption and decryption of login state cookies. You can run `openssl rand -base64 32` to create a secret from your CLI.                                                                                                                                                                                                                                |
| LoginUrl | string | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow.                                                                                                                                                                                                                                                    |
| RedirectUri | string | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint.                                                                                                                                                                                                                                                                         |
| RootDomain | string | Only if using tenant subdomains | The root domain for your application. This value only needs to be specified if you use tenant subdomains in your login and redirect URLs.  The root domain should be set to the portion of the domain following the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. |
| Scopes | string[] | No | The scopes required for authentication. Refer to the docs for [currently supported scopes](https://docs.wristband.dev/docs/oauth2-and-openid-connect-oidc#supported-openid-scopes). The default value is `[openid, offline_access, email]`.                                                                                                                                                              |
| UseCustomDomains | boolean | No | Indicates whether your Wristband application is configured to use custom domains. Defaults to `false`.                                                                                                                                                                                                                                                                                                   |
| UseTenantSubdomains | boolean | No | Indicates whether tenant subdomains are used for your application's authentication endpoints (e.g. login and callback). Defaults to `false`.                                                                                                                                                                                                                                                             |
| WristbandApplicationDomain | string | Yes | The vanity domain of the Wristband application.                                                                                                                                                                                                                                                                                                                                                          |


## API

### `Task<string> Login(HttpContext context, LoginConfig? loginConfig);`

```csharp
// OPTIONAL: Custom configuration for login.
var loginConfig = new LoginConfig
{
    CustomState = new Dictionary<string, object>
    {
        { "referrer", "marketing-campaign-123" }
    },
    DefaultTenantDomainName = "acme-corporation",
    DefaultTenantCustomDomain = "login.acme-corp.com"
};
var wristbandAuthorizeUrl = await wristbandAuth.Login(httpContext, loginConfig);
return Results.Redirect(wristbandAuthorizeUrl);
```

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your Login Endpoint, there are two ways to accomplish getting the `TenantDomainName` information: passing a query parameter or using tenant subdomains.

The `Login()` function can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| CustomState | JSON | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| DefaultTenantDomainName | string | No | An optional default tenant domain name to use for the login request in the event the tenant domain cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| DefaultTenantCustomDomain | string | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |

#### Which Domains Are Used in the Authorize URL?
Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` request query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if subdomains are enabled and the subdomain is present.
3. `tenant_domain` request query parameter: Evaluated if no tenant subdomain is detected.
4. `DefaultTenantCustomDomain` in LoginConfig: Used if none of the above are present.
5. `DefaultTenantDomain` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Tenant Domain Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_domain=customer01
```

Your WristbandAuthConfig would look like the following when creating an SDK instance without any subdomains:

```csharp
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "ic6saso5hzdvbnof3bwgccejxy";
    options.ClientSecret = "30e9977124b13037d035be10d727806f";
    options.LoginStateSecret = "7ffdbecc-ab7d-4134-9307-2dfcc52f7475";
    options.LoginUrl = "https://yourapp.io/auth/login";
    options.RedirectUri = "https://yourapp.io/auth/callback";
    options.WristbandApplicationDomain = "yourapp-yourcompany.us.wristband.dev";
});
```

#### Tenant Subdomains

If your application wishes to utilize tenant subdomains, then you do not need to pass a query param when redirecting to your Login Endpoint. The SDK will parse the tenant subdomain from the URL in order to make the redirection to the Wristband Authorize Endpoint. You will also need to tell the SDK what your application's root domain is in order for it to correctly parse the subdomain.

```sh
GET https://customer01.yourapp.io/auth/login
```

Your AuthConfig would look like the following when creating an SDK instance when using subdomains:

```csharp
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "ic6saso5hzdvbnof3bwgccejxy";
    options.ClientSecret = "30e9977124b13037d035be10d727806f";
    options.LoginStateSecret = "7ffdbecc-ab7d-4134-9307-2dfcc52f7475";
    options.LoginUrl = "https://{tenant_domain}.yourapp.io/auth/login";
    options.RedirectUri = "https://{tenant_domain}.yourapp.io/auth/callback";
    options.RootDomain = "yourapp.io";
    options.UseTenantSubdomains = true;
    options.WristbandApplicationDomain = "yourapp-yourcompany.us.wristband.dev";
});
```

#### Default Tenant Domain Name

For certain use cases, it may be useful to specify a default tenant domain in the event that the `login()` function cannot find a tenant domain in either the query parameters or in the URL subdomain. You can specify a fallback default tenant domain via a `LoginConfig` object:

```csharp
var loginConfig = new LoginConfig
{
    DefaultTenantDomainName = "global"
};
var wristbandAuthorizeUrl = await wristbandAuth.Login(httpContext, loginConfig);
```

#### Tenant Custom Domain Query Param

If your application wishes to utilize tenant custom domains, you can pass the `tenant_custom_domain` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_custom_domain=mytenant.com
```

The tenant custom domain takes precedence over all other possible domains else when present.

#### Default Tenant Custom Domain

For certain use cases, it may be useful to specify a default tenant custom domain in the event that the `Login()` method cannot find a tenant custom domain in the query parameters. You can specify a fallback default tenant custom domain via a `LoginConfig` object:

```csharp
var loginConfig = new LoginConfig
{
    DefaultTenantCustomDomain = "mytenant.com"
};
var wristbandAuthorizeUrl = await wristbandAuth.Login(httpContext, loginConfig);
```

The default tenant custom domain takes precedence over all other possible domains else when present except when the `tenant_custom_domain` query parameter exists in the request.

#### Custom State

Before your Login Endpoint redirects to Wristband, it will create a Login State Cookie to cache all necessary data required in the Callback Endpoint to complete any auth requests. You can inject additional state into that cookie via a `LoginConfig` object:

```csharp
var loginConfig = new LoginConfig
{
    CustomState = new Dictionary<string, object>
    {
        { "referrer", "marketing-campaign-123" }
    },
};
await wristbandAuth.Login(httpContext, loginConfig);
```

> [!WARNING]
> Injecting custom state is an advanced feature, and it is recommended to use `CustomState` sparingly. Most applications may not need it at all. The max cookie size is 4kB. From our own tests, passing a `CustomState` JSON of at most 1kB should be a safe ceiling.

#### Login Hints

Wristband will redirect to your Login Endpoint for workflows like Application-Level Login (Tenant Discovery) and can pass the `login_hint` query parameter as part of the redirect request:

```sh
GET https://customer01.yourapp.io/auth/login?login_hint=user@wristband.dev
```

If the request to your Login Endpoint passes this parameter, it will be appended as part of the redirect request to the Wristband Authorize Endpoint. Typically, the email form field on the Tenant-Level Login page is pre-filled when a user has previously entered their email on the Application-Level Login Page.

#### Return URLs

Users often try to access specific pages within your application that require authentication. Rather than always redirecting them to a default landing page after login, you can create a more seamless experience by returning them to their intended destination.

To implement this, your frontend can include a `return_url` query parameter when redirecting to your Login Endpoint. This URL will be preserved throughout the authentication flow and made available to you in the Callback Endpoint, allowing you to redirect users exactly where they intended to go.

```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and you can choose to send users to that return URL (if necessary) after the SDK's `Callback()` method is done executing.

### `Task<CallbackResult> Callback(HttpContext context);`

```csharp
var callbackResult = await wristbandAuth.Callback(httpContext);
```

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your Callback Endpoint with an authorization code which can be used to exchange for an access token. It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration. The return type of the callback function is a `CallbackResult` object containing the result of what happened during callback execution as well as any accompanying data:

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| CallbackData | CallbackData or undefined | The callback data received after authentication (`COMPLETED` result only). |
| RedirectUrl | string | A URL that you need to redirect to (`REDIRECT_REQUIRED` result only). For some edge cases, the SDK will require a redirect to restart the login flow. |
| Result | CallbackResultType  | Enum representing the end result of callback execution. |

The following are the possible `CallbackResultType` enum values that can be returned from the callback execution:

| CallbackResultType  | Description |
| ------------------- | ----------- |
| COMPLETED  | Indicates that the callback is successfully completed and data is available for creating a session. |
| REDIRECT_REQUIRED  | Indicates that a redirect to the login endpoint is required, and `RedirectUrl` contains the destination. |

When the callback returns a `COMPLETED` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:


| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| AccessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| CustomState | Dictionary<string, object>? | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| ExpiresIn | number | The durtaion from the current time until the access token is expired (in seconds). |
| IdToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| RefreshToken | string? | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| ReturnUrl | string? | The URL to return to after authentication is completed. |
| TenantCustomDomain | string? | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| TenantDomainName | string | The domain name of the tenant the user belongs to. |
| Userinfo | UserInfo | JSON data for the current user retrieved from the Wristband Userinfo Endpoint. The data returned in this object follows the format laid out in the [Wristband Userinfo Endpoint documentation](https://docs.wristband.dev/reference/userinfov1). The exact fields that get returned are based on the scopes you configured in the SDK. |


#### Redirect Responses

There are certain scenarios where instead of callback data being returned by the SDK, a redirect response occurs during execution instead.  The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your Login Endpoint and ultimately to the Wristband-hosted Tenant-Level Login Page URL.
2. Otherwise, the user will be sent to the Wristband-hosted Application-Level Login Page URL (Tenant Discovery).

#### Error Parameters

Certain edge cases are possible where Wristband encounters an error during the processing of an auth request. These are the following query parameters that are sent for those cases to your Callback Endpoint:

| Query Parameter | Description |
| --------------- | ----------- |
| error | Indicates an error that occurred during the Login Workflow. |
| error_description | A human-readable description or explanation of the error to help diagnose and resolve issues more effectively. |

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&error=login_required&error_description=User%20must%20re-authenticate%20because%20the%20specified%20max_age%20value%20has%20elapsed
```

The error types that get automatically resolved in the SDK are:

| Error | Description |
| ----- | ----------- |
| login_required | Indicates that the user needs to log in to continue. This error can occur in scenarios where the user's session has expired, the user is not currently authenticated, or Wristband requires the user to explicitly log in again for security reasons. |
| invalid_grant | Indicates that the authorization code is invalid, expired, or has been revoked. This typically happens when attempting to exchange an authorization code that has already been used. |

For all other error types, the SDK will throw a `WristbandError` object (containing the error and description) that your application can catch and handle. Most errors come from SDK configuration issues during development that should be addressed before release to production.


### `Task<string> Logout(HttpContext context, LogoutConfig? logoutConfig);`

```csharp
// OPTIONAL: Custom configuration for logout.
var logoutConfig = new LogoutConfig
{
    RedirectUrl = "https://custom-logout-landing-location.com",
    RefreshToken = "98yht308hf902hc90wh09",
    TenantDomainName = "acme-corporation",
    TenantCustomDomain = "login.acme-corp.com"
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
return Results.Redirect(wristbandLogoutUrl);
```

When users of your application are ready to log out and/or their application session expires, your frontend should redirect the user to your Logout Endpoint.

```sh
GET https://customer01.yourapp.io/auth/logout
```

If your application created a session, it should destroy it before invoking the `Logout()` method.  This method can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| RedirectUrl | string | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `customApplicationLoginPageUrl` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| RefreshToken | string | No | The refresh token to revoke. |
| TenantCustomDomain | string | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| TenantDomainName | string | No | The domain name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?
Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your Logout Endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `TenantCustomDomain` in LogoutConfig: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if subdomains are enabled and the subdomain is present.
3. `TenantDomainName` in LogoutConfig: Used as the final fallback.

If none of these are specified, the SDK redirects users to the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `Logout()` method, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domain Names

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you will need to explicitly pass it into the LogoutConfig.

```csharp
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09",
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

If your application uses tenant subdomains, then passing the `TenantDomainName` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you will need to explicitly pass it into the LogoutConfig.

```csharp
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09",
    TenantCustomDomain = "mytenant.com",
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then passing both the `TenantDomainName` and `TenantCustomDomain` fields to the LogoutConfig is necessary to ensure all use cases are handled by the SDK.

```csharp
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09",
    TenantCustomDomain = "mytenant.com",
    TenantDomainName = "customer01"
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `RedirectUrl` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```csharp
var logoutConfig = new LogoutConfig
{
    RedirectUrl = "https://custom-logout-landing-location.com",
    RefreshToken = "98yht308hf902hc90wh09"
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

### `Task<TokenData?> RefreshTokenIfExpired(string refreshToken, long expiresAt);`

```csharp
var tokenData = await wristbandAuth.RefreshTokenIfExpired('98yht308hf902hc90wh09', 1710707503788);
```

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your applicaiton needs to ensure that access tokens don't expire until the user's session ends.  You can use the refresh token to generate new access tokens.

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| ExpiresAt | number | Yes | Unix timestamp in milliseconds at which the token expires. |
| RefreshToken | string | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |

If the `RefreshTokenIfExpired()` method finds that your token has not expired yet, it will return `null` as the value, which means your auth middleware can simply continue forward as usual.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
