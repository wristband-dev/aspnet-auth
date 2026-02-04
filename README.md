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

# Wristband Multi-Tenant Authentication SDK for ASP.NET Core (C#)

[![NuGet](https://img.shields.io/nuget/v/Wristband.AspNet.Auth?label=NuGet)](https://www.nuget.org/packages/Wristband.AspNet.Auth/)
[![version number](https://img.shields.io/github/v/release/wristband-dev/aspnet-auth?color=green&label=version)](https://github.com/wristband-dev/aspnet-auth/releases)
[![Actions Status](https://github.com/wristband-dev/aspnet-auth/workflows/Test/badge.svg)](https://github.com/wristband-dev/aspnet-auth/actions)
[![License](https://img.shields.io/github/license/wristband-dev/aspnet-auth)](https://github.com/wristband-dev/aspnet-auth/blob/main/LICENSE)

Enterprise-ready authentication for multi-tenant [ASP.NET Core applications](https://dotnet.microsoft.com/en-us/apps/aspnet) using OAuth 2.1 and OpenID Connect standards.

<br>

## Overview

This SDK provides complete authentication integration with Wristband, including:

- **Login flow** - Redirect to Wristband and handle OAuth callbacks
- **Session management** - Encrypted cookie-based sessions with CSRF protection
- **Token handling** - Automatic access token refresh and validation
- **Logout flow** - Token revocation and session cleanup
- **Multi-tenancy** - Support for tenant subdomains and custom domains

Learn more about Wristband's authentication patterns:

- [Backend Server Integration Pattern](https://docs.wristband.dev/docs/backend-server-integration)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

> **💡 Learn by Example**
>
> Want to see the SDK in action? Check out our [ASP.NET demo application](#wristband-multi-tenant-aspnet-demo-app). The demo showcases real-world authentication patterns and best practices.

<br>

---

<br>

## Table of Contents

- [Migrating From Older SDK Versions](#migrating-from-older-sdk-versions)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [1) Initialize the SDK](#1-initialize-the-sdk)
  - [2) Set Up Session Management](#2-set-up-session-management)
  - [3) Add Auth Endpoints](#3-add-auth-endpoints)
    - [Login Endpoint](#login-endpoint)
    - [Callback Endpoint](#callback-endpoint)
    - [Logout Endpoint](#logout-endpoint)
    - [Session Endpoint](#session-endpoint)
    - [Token Endpoint](#token-endpoint)
  - [4) Protect Your API Routes](#4-protect-your-api-routes)
  - [5) Use Your Access Token with APIs](#5-use-your-access-token-with-apis)
- [Wristband Auth Service Configuration Options](#wristband-auth-service-configuration-options)
  - [AddWristbandAuth](#addwristbandauth)
  - [Discover](#discover)
- [Auth API](#auth-api)
  - [Login](#login)
  - [Callback](#callback)
  - [Logout](#logout)
  - [RefreshTokenIfExpired](#refreshtokenifexpired)
- [Session Management](#session-management)
  - [Session Configuration](#session-configuration)
  - [The Session Structure](#the-session-structure)
  - [Session API](#session-api)
    - [CreateSessionFromCallback()](#createsessionfromcallback)
    - [CreateSession()](#createsession)
    - [DestroySession()](#destroysession)
    - [SetSessionClaim()](#setsessionclaim)
    - [RemoveSessionClaim()](#removesessionclaim)
    - [GetSessionClaim()](#getsessionclaim)
    - [Typed Getters](#typed-getters)
    - [GetSessionResponse()](#getsessionresponse)
    - [GetTokenResponse()](#gettokenresponse)
  - [CSRF Protection](#csrf-protection)
  - [Session Encryption Configuration](#session-encryption-configuration)
- [Authorization Policies](#authorization-policies)
  - [Session-Based Authentication](#session-based-authentication)
  - [JWT Bearer Token Authentication](#jwt-bearer-token-authentication)
  - [Multi-Strategy Authentication](#multi-strategy-authentication)
- [Advanced Configuration](#advanced-configuration)
  - [Configuration Sources](#configuration-sources)
  - [Named Services](#named-services-multiple-oauth2-clients)
  - [Combining Authorization Policies](#combining-authorization-policies)
  - [Session Encryption with Persistent Key Storage](#session-encryption-with-persistent-key-storage)
- [Related Wristband SDKs](#related-wristband-sdks)
- [Wristband Multi-Tenant ASP.NET Demo App](#wristband-multi-tenant-aspnet-demo-app)
- [Questions](#questions)

<br>

---

<br>

## Migrating From Older SDK Versions

On an older version of our SDK? Check out our migration guide:

- [Instructions for migrating to Version 4.x (latest)](migration/v4/README.md)
- [Instructions for migrating to Version 3.x](migration/v3/README.md)
- [Instructions for migrating to Version 2.x](migration/v2/README.md)
- [Instructions for migrating to Version 1.x](migration/v1/README.md)

<br>

## Prerequisites

> **⚡ Try Our ASP.NET Quickstart!**
>
> For the fastest way to get started with ASP.NET authentication, follow our [Quick Start Guide](https://docs.wristband.dev/docs/auth-quick-start). It walks you through setting up a working ASP.NET app with Wristband authentication in minutes. Refer back to this README for comprehensive documentation and advanced usage patterns.

Before installing, ensure you have:

- [.NET SDK](https://dotnet.microsoft.com/download) >= 8.0
- Your preferred package manager (dotnet CLI, NuGet Package Manager)

<br>

## Installation

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
  <PackageReference Include="Wristband.AspNet.Auth" Version="4.1.0" />
</ItemGroup>
```

<br>

## Usage

### 1) Initialize the SDK

Register the Wristband authentication service in your `Program.cs` file:

```csharp
// Program.cs
using Wristband.AspNet.Auth;

namespace YourApp;

var builder = WebApplication.CreateBuilder(args);

// Register Wristband authentication
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "<your-client-id>";
    options.ClientSecret = "<your-client-secret>";
    options.WristbandApplicationVanityDomain = "<your-wristband-application-vanity-domain>";
});

var app = builder.Build();

// ... other middleware and routes ...

app.Run();
```

> **⚠️ Security Note:**
>
> The example above shows values inline for simplicity. In real applications, load secrets from environment variables, configuration files, or a secure secrets management system. Never commit secrets to source control.

<br>

## 2) Set Up Session Management

This Wristband authentication SDK is unopinionated about how you store and manage your application session data after the user has authenticated. We typically recommend cookie-based sessions due to it being lighter-weight and not requiring a backend session store like Redis or other technologies. We recommend using ASP.NET Core's built-in cookie authentication along with Wristband's default security settings and error responses.

### Configure and Register Middlewares

Configure ASP.NET Core's cookie authentication and authorization middleware with Wristband's recommended security settings as well as the Wristband session middleware in `Program.cs`:

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Wristband.AspNet.Auth;

namespace YourApp;

var builder = WebApplication.CreateBuilder(args);

// Register Wristband auth service (from step 1)
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "<your-client-id>";
    options.ClientSecret = "<your-client-secret>";
    options.WristbandApplicationVanityDomain = "<your-wristband-application-vanity-domain>";
});

// Configure zero-infrastructure session encryption.
// Derives encryption keys from a shared secret - works across all deployment types
// (single-server, multi-server, Kubernetes, serverless) without Redis or databases.
builder.Services.AddInMemoryKeyDataProtection("your-secret-key-min-32-characters-long");

// Add cookie-based authentication; stores session data in encrypted browser cookie
// NOTE: Default to Cookie auth for access to session data on all endpoints.
// Protected endpoints can override the default with authorization policies, if needed.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => options.UseWristbandSessionConfig());

// Register Wristband authorization handler
// Validates session cookies and JWT tokens; refreshes expired access tokens
builder.Services.AddWristbandAuthorizationHandler();

// Add authorization policies
// Defines "WristbandSession" and "WristbandJwt" authorization policies for protecting endpoints
builder.Services.AddAuthorization(options => options.AddWristbandDefaultPolicies());

var app = builder.Build();

// Authentication: Populates HttpContext.User from session cookie
app.UseAuthentication();

// Authorization: Enforces authorization policies on protected endpoints
app.UseAuthorization();

// Wristband Session: Saves updated session data to cookie after endpoints complete
app.UseWristbandSessionMiddleware();

// ... your API routes here...

app.Run();
```

**What each piece does:**

| Component | Purpose |
| --------- | ------- |
| **`AddInMemoryKeyDataProtection()`** | Zero-infrastructure session encryption that works across all deployment types (single-server, Kubernetes, serverless, etc.) by deriving encryption keys from a shared secret. No Redis or databases required. See [Session Encryption Configuration](#session-encryption-configuration) for setup. |
| **`AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)`** | Sets cookie authentication as the default scheme. This means .NET will automatically attempt to read and populate `HttpContext.User` from the session cookie on every request - including unprotected endpoints. Without this, session data would only be available on endpoints that explicitly require authentication. |
| **`AddCookie()`** | Configures how session cookies work (security, expiration, etc.). |
| **`UseWristbandSessionConfig()`** | Applies Wristband's recommended security defaults for session cookies. |
| **`AddWristbandAuthorizationHandler()`** | Registers the handler that validates sessions, refreshes tokens, and enforces CSRF protection. |
| **`AddWristbandDefaultPolicies()`** | Registers "WristbandSession" and "WristbandJwt" authorization policies for protecting endpoints. |
| **`UseAuthentication()`** | Reads the session cookie on each request and populates `HttpContext.User`. |
| **`UseAuthorization()`** | Checks if the user is authorized to access protected endpoints based on policies. |
| **`UseWristbandSessionMiddleware()`** | Automatically saves session changes to the encrypted cookie after your endpoint completes (more details in [Session Management](#session-management)). |

**Wristband session defaults:**

- **HttpOnly cookies** - Prevents JavaScript access to the cookie
- **Secure cookies** - Cookie only sent over HTTPS
- **SameSite=Lax** - Provides CSRF protection for most scenarios
- **1-hour sliding expiration** - Session extends on each request (rolling sessions)
- **API-friendly error codes** - Returns 401/403 status codes instead of redirects

> **⚠️ Middleware Order Matters:**
>
> Always call `UseAuthentication()` before `UseAuthorization()`, and both before `UseWristbandSessionMiddleware()`.

<br>

## 3) Add Auth Endpoints

There are **four core API endpoints** your ASP.NET server should expose to facilitate authentication workflows in Wristband:

- Login Endpoint
- Callback Endpoint
- Logout Endpoint
- Session Endpoint

There's also one additional endpoint you can implement depending on your authentication needs:

- Token Endpoint (optional)

<br>

#### Register Auth Endpoints

First, create a dedicated file for your authentication endpoints (e.g., `AuthRoutes.cs`). This keeps your auth logic organized and separate from your application routes.

```csharp
// AuthRoutes.cs
using Microsoft.AspNetCore.Builder;
using Wristband.AspNet.Auth;

namespace YourApp;

public static class AuthRoutes
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        // Route path can be whatever you prefer
        var authRoutes = app.MapGroup("/api/auth");

        // Auth endpoints will go here...

        return authRoutes;
    }
}
```

Then, include your auth routes in your `Program.cs`:

> **⚠️ Order Matters:**
>
> Always register middleware (`UseAuthentication()`, `UseAuthorization()`, `UseWristbandSessionMiddleware()`) **before** mapping routes. Middleware only applies to routes registered after it.

```csharp
// Program.cs

using YourApp;

namespace YourApp;

var builder = WebApplication.CreateBuilder(args);

// ... middleware configuration ...

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseWristbandSessionMiddleware();

// Map auth endpoints
app.MapAuthEndpoints();

app.Run();
```

From here, you'll implement the auth endpoints in the `AuthRoutes.cs` file.

<br>

#### Login Endpoint

The goal of the Login Endpoint is to initiate an auth request by redirecting to the [Wristband Authorization Endpoint](https://docs.wristband.dev/reference/authorizev1). It will store any state tied to the auth request in a Login State Cookie, which will later be used by the Callback Endpoint. The frontend of your application should redirect to this endpoint when users need to log in to your application.

```csharp
// AuthRoutes.cs (continued)

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

namespace YourApp;

public static class AuthRoutes
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        var authRoutes = app.MapGroup("/api/auth");

        // Login Endpoint - Route path can be whatever you prefer
        authRoutes.MapGet("/login", async (
            HttpContext httpContext,
            IWristbandAuthService wristbandAuth) =>
        {
            // Call the Wristband Login() method and redirect to the resulting URL.
            var wristbandAuthorizeUrl = await wristbandAuth.Login(httpContext, null);
            return Results.Redirect(wristbandAuthorizeUrl);
        })

        return authRoutes;
    }
}
```

<br>

#### Callback Endpoint

The goal of the Callback Endpoint is to receive incoming calls from Wristband after the user has authenticated and ensure that the Login State cookie contains all auth request state in order to complete the Login Workflow. From there, it will call the [Wristband Token Endpoint](https://docs.wristband.dev/reference/tokenv1) to fetch necessary JWTs, call the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) to get the user's data, and create a session for the application containing the JWTs and user data.

```csharp
// AuthRoutes.cs (continued)

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

namespace YourApp;

public static class AuthRoutes
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        // ...

        // Callback Endpoint - Route path can be whatever you prefer
        authRoutes.MapGet("/callback", async (
            HttpContext httpContext,
            IWristbandAuthService wristbandAuth) =>
        {
            // Call the Wristband Callback() method to get results, token data, and user info.
            var callbackResult = await wristbandAuth.Callback(httpContext);

            // For some edge cases, the SDK will require a redirect to restart the login flow.
            if (callbackResult.Type == CallbackResultType.RedirectRequired)
            {
                return Results.Redirect(callbackResult.RedirectUrl);
            }

            // Create a session in your app for the authenticated user.
            httpContext.CreateSessionFromCallback(callbackResult.CallbackData, customClaims);

            // Return the callback response that redirects to your app.
            return Results.Redirect(callbackResult.CallbackData.ReturnUrl ?? "http://localhost:6001");
        })

        return authRoutes;
    }
};
```

<br>

#### Logout Endpoint

The goal of the Logout Endpoint is to destroy the application's session that was established during the Callback Endpoint execution. If refresh tokens were requested during the Login Workflow, then a call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) will occur. It then will redirect to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1) in order to destroy the user's authentication session within the Wristband platform. From there, Wristband will send the user to the Tenant-Level Login Page (unless configured otherwise).

```csharp
// AuthRoutes.cs (continued)

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

namespace YourApp;

public static class AuthRoutes
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        // ...

        // Logout Endpoint - Route path can be whatever you prefer
        authRoutes.MapGet("/logout", async (
            HttpContext httpContext,
            IWristbandAuthService wristbandAuth) =>
        {
            // Grab necessary session fields for the Logout() method.
            var logoutConfig = new LogoutConfig
            {
                RefreshToken = httpContext.GetRefreshToken(),
                TenantCustomDomain = httpContext.GetTenantCustomDomain(),
                TenantName = httpContext.GetTenantName(),
            };
    
            // Destroy your application session.
            httpContext.DestroySession();

            // Call the Wristband Logout() method and redirect to the resulting URL.
            var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
            return Results.Redirect(wristbandLogoutUrl);
        });

        return authRoutes;
    }
}
```

<br>

#### Session Endpoint

> [!NOTE]
> This endpoint is required for Wristband frontend SDKs to function. For more details, see the [Wristband Session Management documentation](https://docs.wristband.dev/docs/session-management-backend-server).

Wristband frontend SDKs require a Session Endpoint in your backend to verify authentication status and retrieve session metadata. Create a protected session endpoint that uses `HttpContext.GetSessionResponse()` to return the session response format expected by Wristband's frontend SDKs. The response model will always have a `userId` and a `tenantId` in it. You can include any additional data for your frontend by customizing the `metadata` parameter (optional), which requires JSON-serializable values. **The response must not be cached**.

> **⚠️ Important:**
> Make sure to protect this endpoint with `RequireWristbandSession()`!

```csharp
// AuthRoutes.cs (continued)

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

namespace YourApp;

public static class AuthRoutes
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        // ...

        // Session Endpoint - Route path can be whatever you prefer
        authRoutes.MapGet("/session", async (HttpContext httpContext) =>
        {
            // Session response with optional custom metadata (as expected by frontend SDK)
            var response = httpContext.GetSessionResponse(metadata: new
            {
                email = httpContext.GetSessionClaim("email"),
                fullName = httpContext.GetSessionClaim("fullName")
            });
            return Results.Ok(response);
        })
        .RequireWristbandSession();  // Protect with session auth

        return authRoutes;
    }
}
```

The Session Endpoint returns a `SessionResponse` model to your frontend:

```json
{
  "userId": "user_xyz789",
  "tenantId": "tenant_abc123",
  "metadata": {
    "email": "user@example.com",
    "fullName": "Jane Doe"
  }
}
```

<br>

#### Token Endpoint (Optional)

> [!NOTE]
> This endpoint is required when your frontend needs to make authenticated API requests directly to Wristband or other protected services. For more details, see the [Wristband documentation on using access tokens from the frontend](https://docs.wristband.dev/docs/authenticating-api-requests-with-bearer-tokens#using-access-tokens-from-the-frontend).
>
> If your application doesn't need frontend access to tokens (e.g., all API calls go through your backend), you can skip this endpoint.

Some applications require the frontend to make direct API calls to Wristband or other protected services using the user's access token. The Token Endpoint provides a secure way for your frontend to retrieve the current access token and its expiration time. Create a protected token endpoint that uses `HttpContext.GetTokenResponse()` to return the token response format expected by Wristband's frontend SDKs.  **The response must not be cached**.

> **⚠️ Important:**
> Make sure to protect this endpoint with `RequireWristbandSession()`!

```csharp
// AuthRoutes.cs (continued)

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Wristband.AspNet.Auth;

public static class AuthRoutes
{
    public static RouteGroupBuilder MapAuthEndpoints(this WebApplication app)
    {
        // ...

        // Token Endpoint - Route path can be whatever you prefer
        authRoutes.MapGet("/token", async (HttpContext httpContext) =>
        {
            var response = httpContext.GetTokenResponse();
            return Results.Ok(response);
        })
        .RequireWristbandSession();  // Protect with session auth

        return authRoutes;
    }
}
```

The Token Endpoint returns a `TokenResponse` model to your frontend:

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": 1735689600000
}
```

Your frontend can then use the `accessToken` in the Authorization header when making API requests:

```typescript
const tokenResponse = await fetch('/auth/token');
const { accessToken } = await tokenResponse.json();

// Use token to call Wristband API
const userResponse = await fetch('https:///api/v1/users/123', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});
```

<br>

### 4) Protect Your API Routes

Once your auth endpoints are set up, you can protect routes that require authentication using ASP.NET Core's authorization policies. The SDK provides multiple authentication strategies depending on your application's needs.

> **💡 Multiple Auth Strategies Available**
>
> This SDK supports session-based authentication, JWT bearer tokens, and multi-strategy authentication (combining both). For the full range of options, see the [Authorization Policies](#authorization-policies) section.

Use the `RequireWristbandSession()` extension to protect individual endpoints or entire route groups:

```csharp
// Example: Protect individual endpoints
app.MapGet("/api/protected", (HttpContext httpContext) =>
{
    var userId = httpContext.GetUserId();
    return Results.Ok(new { message = $"Hello, {userId}!" });
})
.RequireWristbandSession();

// Example: Protect entire route groups
var protectedRoutes = app.MapGroup("/api/protected");
protectedRoutes.RequireWristbandSession(); // All routes in this group are protected

protectedRoutes.MapGet("/data", (HttpContext httpContext) =>
{
    return Results.Ok(new { data = "Protected data" });
});

protectedRoutes.MapPost("/orders", (HttpContext httpContext) =>
{
    var userId = httpContext.GetUserId();
    // Process order...
    return Results.Ok(new { status = "created" });
});
```

The `RequireWristbandSession()` policy automatically:

- ✅ **Validates authentication** - Checks session validity
- ✅ **Refreshes expired tokens** - Only when `refreshToken` and `expiresAt` are present in session (with up to 3 retry attempts)
- ✅ **Extends session expiration** - Rolling session window on each authenticated request (via session middleware)
- ✅ **Validates CSRF tokens** - Checks CSRF tokens to prevent cross-site request forgery attacks (only if enabled)
- ✅ **Returns 401 for unauthenticated requests** - Automatically rejects invalid or missing sessions

<br>

### 5) Use Your Access Token with APIs

> [!NOTE]
> This section is only applicable if you need to call Wristband APIs or protect your own backend services with Wristband tokens.

If you intend to utilize Wristband APIs within your application or secure any backend APIs or downstream services using the access token provided by Wristband, you must include this token in the `Authorization` HTTP request header.
```
Authorization: Bearer <access_token_value>
```

The access token is available in different ways depending on your authentication strategy.

#### Session-Based Access Tokens

When using session-based authentication, the access token is stored in the session and accessible via the `.GetAccessToken()` session extension method:

```csharp
app.MapPost("/api/orders", async (HttpContext httpContext, IHttpClientFactory httpClientFactory) =>
{
    try
    {
        var orderData = await httpContext.Request.ReadFromJsonAsync<Order>();
        await SaveOrderToDatabase(orderData);
        
        // Get access token from session
        var accessToken = httpContext.GetAccessToken();
        
        // Pass token to downstream API
        var httpClient = httpClientFactory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/email-receipt");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Content = JsonContent.Create(orderData);
        
        var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        return Results.Ok(new { status = "created" });
    }
    catch (Exception ex)
    {
        return Results.Problem(detail: $"Error: {ex.Message}", statusCode: 500);
    }
})
.RequireWristbandSession();
```

#### JWT Bearer Access Tokens

> **💡 JWT Authentication**
>
> For full details on how to set up and use JWT authentication, see the [Authorization Policies](#authorization-policies) section.

When using JWT authentication via `RequireWristbandJwt()`, the raw JWT string is available via the `GetJwt()` JWT extension method.

```csharp
app.MapPost("/api/orders", async (HttpContext httpContext, IHttpClientFactory httpClientFactory) =>
{
    var orderData = await httpContext.Request.ReadFromJsonAsync<Order>();
    await SaveOrderToDatabase(orderData);
    
    // Get JWT token from request
    var jwt = httpContext.GetJwt();
    
    // Pass token to downstream API
    var httpClient = httpClientFactory.CreateClient();
    var request = new HttpRequestMessage(HttpMethod.Post, "https://api.example.com/email-receipt");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
    request.Content = JsonContent.Create(orderData);
    
    var response = await httpClient.SendAsync(request);
    response.EnsureSuccessStatusCode();
    return Results.Ok(new { status = "created" });
})
.RequireWristbandJwt();  // Protect endpoint with Bearer token JWT (requires additional setup)
```

#### Using Access Tokens from the Frontend

For scenarios where your frontend needs to make direct API calls with the user's access token, use the [Token Endpoint](#token-endpoint-optional) to securely retrieve the current access token.

<br>

---

<br>

## Wristband Auth Service Configuration Options

The `AddWristbandAuth()` extension is used to instatiate the Wristband Auth SDK. It takes a `WristbandAuthConfig` type as an argument.

```csharp
// Direct Configuration
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "direct-client";
    options.ClientSecret = "direct-secret";
    options.LoginStateSecret = "this-is-a-secret-that-is-at-least-32-chars";
    options.LoginUrl = "https://login.url";
    options.RedirectUri = "https://redirect.uri";
    options.WristbandApplicationVanityDomain = "wristband.domain";
});
```

| AuthConfig Field | Type | Required | Auto-Configurable | Description |
| ---------------- | ---- | -------- | ----------------- | ----------- |
| AutoConfigureEnabled | boolean | No | _N/A_ | Flag that tells the SDK to automatically set some of the SDK configuration values by calling to Wristband's SDK Auto-Configuration Endpoint. Any manually provided configurations will take precedence over the configs returned from the endpoint. Auto-configure is enabled by default. When disabled, if manual configurations are not provided, then an error will be thrown. |
| ClientId | string | Yes | No | The ID of the Wristband client. |
| ClientSecret | string | Yes | No | The client's secret. |
| CustomApplicationLoginPageUrl | string | No | Yes | Custom Application-Level Login Page URL (i.e. Tenant Discovery Page URL). This value only needs to be provided if you are self-hosting the application login page. By default, the SDK will use your Wristband-hosted Application-Level Login page URL. If this value is provided, the SDK will redirect to this URL in certain cases where it cannot resolve a proper Tenant-Level Login URL. |
| DangerouslyDisableSecureCookies | boolean | No | No | USE WITH CAUTION: If set to `true`, the "Secure" attribute will not be included in any cookie settings. This should only be done when testing in local development environments that don't have HTTPS enabed.  If not provided, this value defaults to `false`. |
| IsApplicationCustomDomainActive | boolean | No | Yes | Indicates whether your Wristband application is configured with an application-level custom domain that is active. This tells the SDK which URL format to use when constructing the Wristband Authorize Endpoint URL. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `DefaultTenantCustomDomain` config.  Defaults to `false`. |
| LoginStateSecret | string | No | No | A 32 character (or longer) secret used for encryption and decryption of login state cookies. If not provided, it will default to using the client secret. For enhanced security, it is recommended to provide a value that is unique from the client secret. You can run `openssl rand -base64 32` to create a secret from your CLI. |
| LoginUrl | string | Only when `AutoConfigureEnabled` is set to `false` | Yes | The URL of your application's login endpoint.  This is the endpoint within your application that redirects to Wristband to initialize the login flow. If you intend to use tenant subdomains in your Login Endpoint URL, then this value must contain the `{tenant_name}` token. For example: `https://{tenant_name}.yourapp.com/auth/login`. |
| ParseTenantFromRootDomain | string | Only if using tenant subdomains in your application | Yes | The root domain for your application. This value only needs to be specified if you intend to use tenant subdomains in your Login and Callback Endpoint URLs.  The root domain should be set to the portion of the domain that comes after the tenant subdomain.  For example, if your application uses tenant subdomains such as `tenantA.yourapp.com` and `tenantB.yourapp.com`, then the root domain should be set to `yourapp.com`. This has no effect on any tenant custom domains passed to your Login Endpoint either via the `tenant_custom_domain` query parameter or via the `default_tenant_custom_domain` config. When this configuration is enabled, the SDK extracts the tenant subdomain from the host and uses it to construct the Wristband Authorize URL. |
| RedirectUri | string | Only when `AutoConfigureEnabled` is set to `false` | Yes | The URI that Wristband will redirect to after authenticating a user.  This should point to your application's callback endpoint. If you intend to use tenant subdomains in your Callback Endpoint URL, then this value must contain the `{tenant_name}` token. For example: `https://{tenant_name}.yourapp.com/auth/callback`. |
| Scopes | string[] | No | No | The scopes required for authentication. Specified scopes can alter which data is returned from the `callback()` method's `callback_data` return type.  Refer to the [Wristband Authorize API](https://docs.wristband.dev/reference/authorizev1) documentation for currently supported scopes. The default value is `["openid", "offline_access", "email"]`. |
| TokenExpirationBuffer | int | No | No | Buffer time (in seconds) to subtract from the access token’s expiration time. This causes the token to be treated as expired before its actual expiration, helping to avoid token expiration during API calls. Defaults to 60 seconds. |
| WristbandApplicationVanityDomain | string | Yes | No | The vanity domain of the Wristband application. |

<br>

### `AddWristbandAuth()`

```csharp
builder.Services.AddWristbandAuth(options => { /* configure options */ });
```

This extension method registers the Wristband authentication services using lazy auto-configuration. Auto-configuration is enabled by default and will fetch any missing configuration values from the Wristband SDK Configuration Endpoint when any auth function is first called (i.e. Login, Callback, etc.). Set `AutoConfigureEnabled` to `false` to prevent the SDK from making an API request to the Wristband SDK Configuration Endpoint. In the event auto-configuration is disabled, you must manually configure all required values. Manual configuration values take precedence over auto-configured values.

| Method | When Config is Fetched | Use When |
| ------ | ---------------------- | -------- |
| AddWristbandAuth() (default) | Lazily, on first auth method call (login, callback, etc.) | Standard usage - allows your app to start without waiting for config |
| Discover() | Eagerly, immediately when called | You want to fail fast at startup if auto-config is unavailable |

**Minimal config with auto-configure (default behavior)**
```csharp
// appsettings.json
{
  "WristbandAuthConfig": {
    "ClientId": "<your_client_id>",
    "WristbandApplicationVanityDomain": "<your_wristband_application_vanity_domain>"
  }
}

// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddWristbandAuth(options =>
{
    var authConfig = builder.Configuration.GetSection("WristbandAuthConfig");
    options.ClientId = authConfig["ClientId"];
    options.ClientSecret = authConfig["ClientSecret"]; // From user secrets
    options.WristbandApplicationVanityDomain = authConfig["WristbandApplicationVanityDomain"];
});
```

**Manual override with partial auto-configure for some fields**
```csharp
// appsettings.json
{
  "WristbandAuthConfig": {
    "ClientId": "<your_client_id>",
    "WristbandApplicationVanityDomain": "<your_wristband_application_vanity_domain>",
    "LoginUrl": "https://yourapp.io/auth/login"
  }
}

// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddWristbandAuth(options =>
{
    var authConfig = builder.Configuration.GetSection("WristbandAuthConfig");
    options.ClientId = authConfig["ClientId"];
    options.ClientSecret = authConfig["ClientSecret"]; // From user secrets
    options.WristbandApplicationVanityDomain = authConfig["WristbandApplicationVanityDomain"];
    options.LoginUrl = authConfig["LoginUrl"]; // Manually override "LoginUrl"
    // "RedirectUri" will be auto-configured
});
```

**Auto-configure disabled**
```csharp
// appsettings.json
{
  "WristbandAuthConfig": {
    "AutoConfigureEnabled": false,
    "ClientId": "<your_client_id>",
    "WristbandApplicationVanityDomain": "auth.custom.com",
    "IsApplicationCustomDomainActive": true,
    "LoginUrl": "https://{tenant_name}.custom.com/auth/login",
    "RedirectUri": "https://{tenant_name}.custom.com/auth/callback",
    "ParseTenantFromRootDomain": "custom.com"
  }
}

// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddWristbandAuth(options =>
{
    var authConfig = builder.Configuration.GetSection("WristbandAuthConfig");
    options.AutoConfigureEnabled = authConfig.GetValue<bool>("AutoConfigureEnabled");
    options.ClientId = authConfig["ClientId"];
    options.ClientSecret = authConfig["ClientSecret"]; // From user secrets
    options.WristbandApplicationVanityDomain = authConfig["WristbandApplicationVanityDomain"];
    // Must manually configure non-auto-configurable fields
    options.IsApplicationCustomDomainActive = authConfig.GetValue<bool>("IsApplicationCustomDomainActive");
    options.LoginUrl = authConfig["LoginUrl"];
    options.RedirectUri = authConfig["RedirectUri"];
    options.ParseTenantFromRootDomain = authConfig["ParseTenantFromRootDomain"];
});
```

<br>

### `Discover()`

This method performs eager auto-configuration on an existing `IWristbandAuthService` instance. Unlike the default lazy auto-configuration behavior, this method immediately fetches and resolves all auto-configuration values from the Wristband SDK Configuration Endpoint during the call. This is useful when you want to fail fast if auto-configuration is unavailable, or when you need configuration values resolved before making any auth method calls. Manual configuration values take precedence over auto-configured values.

> [!WARNING]
> NOTE: This method can only be called when `AutoConfigureEnabled` is `true`. If auto-configuration is disabled, a `WristbandError` will be thrown.

**Eager auto-configure with error handling**
```csharp
// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

// Configure the service
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "your-client-id";
    options.ClientSecret = "your-client-secret";
    options.WristbandApplicationVanityDomain = "auth.yourapp.io";
});

var app = builder.Build();

try
{
    // Get the service instance and perform eager auto-configuration
    var wristbandAuth = app.Services.GetRequiredService<IWristbandAuthService>();
    await wristbandAuth.Discover();
    //
    // ...Configuration is now resolved and validated...
    //
}
catch (WristbandError ex)
{
    Console.WriteLine($"Auto-configuration failed: {ex.ErrorDescription}");
}
```

<br>

## Auth API

### Login()

```csharp
Task<string> Login(HttpContext context, LoginConfig? loginConfig);
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| context | HttpContext | Yes | The ASP.NET HttpContext object. |
| loginConfig | LoginConfig | No | Optional configuration if your application needs custom behavior. |

Wristband requires that your application specify a Tenant-Level domain when redirecting to the Wristband Authorize Endpoint when initiating an auth request. When the frontend of your application redirects the user to your ASP.NET Login Endpoint, there are two ways to accomplish getting the `TenantName` information: passing a query parameter or using tenant subdomains.

```csharp
var wristbandAuthorizeUrl = await wristbandAuth.Login(httpContext);
```

The `Login()` method can also take optional configuration if your application needs custom behavior:

| LoginConfig Field | Type | Required | Description |
| ----------------- | ---- | -------- | ----------- |
| CustomState | JSON | No | Additional state to be saved in the Login State Cookie. Upon successful completion of an auth request/login attempt, your Callback Endpoint will return this custom state (unmodified) as part of the return type. |
| DefaultTenantName | string | No | An optional default tenant name to use for the login request in the event the tenant name cannot be found in either the subdomain or query parameters (depending on your subdomain configuration). |
| DefaultTenantCustomDomain | string | No | An optional default tenant custom domain to use for the login request in the event the tenant custom domain cannot be found in the query parameters. |
| ReturnUrl | string | No | The URL to return to after authentication is completed. If a value is provided, then it takes precedence over the `return_url` request query parameter. |

#### Which Domains Are Used in the Authorize URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Authorize URL, which your login endpoint will redirect users to during the login flow. The selection follows this precedence order:

1. `tenant_custom_domain` request query parameter: If provided, this takes top priority.
2. Tenant subdomain in the URL: Used if subdomains are enabled and the subdomain is present.
3. `tenant_name` request query parameter: Evaluated if no tenant subdomain is detected.
4. `DefaultTenantCustomDomain` in LoginConfig: Used if none of the above are present.
5. `DefaultTenantName` in LoginConfig: Used as the final fallback.

If none of these are specified, the SDK returns the URL for the Application-Level Login (Tenant Discovery) Page.

#### Tenant Name Query Param

If your application does not wish to utilize subdomains for each tenant, you can pass the `tenant_name` query parameter to your Login Endpoint, and the SDK will be able to make the appropriate redirection to the Wristband Authorize Endpoint.

```sh
GET https://yourapp.io/auth/login?tenant_name=customer01
```

Your WristbandAuthConfig would look like the following when creating an SDK instance without any subdomains:

```csharp
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "ic6saso5hzdvbnof3bwgccejxy";
    options.ClientSecret = "30e9977124b13037d035be10d727806f";
    options.LoginUrl = "https://yourapp.io/auth/login";
    options.RedirectUri = "https://yourapp.io/auth/callback";
    options.WristbandApplicationVanityDomain = "yourapp-yourcompany.us.wristband.dev";
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
    options.LoginUrl = "https://{tenant_name}.yourapp.io/auth/login";
    options.RedirectUri = "https://{tenant_name}.yourapp.io/auth/callback";
    options.ParseTenantFromRootDomain = "yourapp.io";
    options.WristbandApplicationVanityDomain = "yourapp-yourcompany.us.wristband.dev";
});
```

#### Default Tenant Name

For certain use cases, it may be useful to specify a default tenant name in the event that the `Login()` method cannot find a tenant name in either the query parameters or in the URL subdomain. You can specify a fallback default tenant name via a `LoginConfig` object:

```csharp
var loginConfig = new LoginConfig
{
    DefaultTenantName = "global"
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

It is possible that users will try to access a location within your application that is not some default landing page. In those cases, they would expect to immediately land back at that desired location after logging in.  This is a better experience for the user, especially in cases where they have application URLs bookmarked for convenience.

Given that your frontend will redirect users to your Login Endpoint, you can either include it in your Login Config:

```csharp
var loginConfig = new LoginConfig
{
    ReturnUrl = "https://customer01.yourapp.io/settings/profile"
};
await wristbandAuth.Login(httpContext, loginConfig);
```

...or you can pass a `return_url` query parameter when redirecting to your Login Endpoint:


```sh
GET https://customer01.yourapp.io/auth/login?return_url=https://customer01.yourapp.io/settings/profile
```

The return URL is stored in the Login State Cookie, and it is available to you in your Callback Endpoint after the SDK's `Callback()` method is done executing. You can choose to send users to that return URL (if necessary). The Login Config takes precedence over the query parameter in the event a value is provided for both.

##### Return URL Preservation During Tenant Discovery

When the `Login()` method cannot resolve a tenant domain from the request (subdomain, query parameters, or defaults), the SDK redirects users to the Application-Level Login (Tenant Discovery) Page. To ensure a seamless user experience, any provided return URL values are automatically preserved by appending them to the `state` query parameter. This allows the return URL to be propagated back to the Login Endpoint once tenant discovery is complete, ensuring users land at their originally intended destination after authentication.

<br>

### Callback()

```csharp
Task<CallbackResult> Callback(HttpContext context);
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| context | HttpContext | Yes | The ASP.NET HttpContext object. |

After a user authenticates on the Tenant-Level Login Page, Wristband will redirect to your ASP.NET Callback Endpoint with an authorization code which can be used to exchange for an access token.

```csharp
var callbackResult = await wristbandAuth.Callback(httpContext);
```

It will also pass the state parameter that was generated during the Login Endpoint.

```sh
GET https://customer01.yourapp.io/auth/callback?state=f983yr893hf89ewn0idjw8e9f&code=shcsh90jf9wc09j9w0jewc
```

The SDK will validate that the incoming state matches the Login State Cookie, and then it will call the Wristband Token Endpoint to exchange the authorizaiton code for JWTs. Lastly, it will call the Wristband Userinfo Endpoint to get any user data as specified by the `scopes` in your SDK configuration.

The return type of the callback method is a `CallbackResult` object containing the result of what happened during callback execution as well as any accompanying data.

**CallbackResult Types:**

The following are the possible `CallbackResultType` enum values that can be returned from the callback execution:

| CallbackResultType  | Description |
| ------------------- | ----------- |
| `Completed`  | Indicates that the callback is successfully completed and data is available for creating a session. |
| `RedirectRequired`  | Indicates that a redirect to the login endpoint is required, and `RedirectUrl` contains the destination. |

<br>

**All Possible CallbackResult Fields:**

| CallbackResult Field | Type | Description |
| -------------------- | ---- | ----------- |
| CallbackData | `CallbackData` or undefined | The callback data received after authentication (`Completed` result only). |
| Reason | string | A description of why a redirect is required (`RedirectRequired` result only). |
| RedirectUrl | string | A URL that you need to redirect to (`RedirectRequired` result only). For some edge cases, the SDK will require a redirect to restart the login flow. |
| Type | `CallbackResultType`  | Enum representing the end result of callback execution. |

**CallbackFailureReason Enum:**

When a redirect is required, the `reason` field indicates why the callback failed:

| Value | Description |
| ----- | ----------- |
| `MissingLoginState` | Login state cookie was not found (cookie expired or bookmarked callback URL) |
| `InvalidLoginState` | Login state validation failed (possible CSRF attack or cookie tampering) |
| `LoginRequired` | Wristband returned a login_required error (session expired or max_age elapsed) |
| `InvalidGrant` | Authorization code was invalid, expired, or already used |

<br>

**CallbackData:**

When the callback returns a `Completed` result, all of the token and userinfo data also gets returned. This enables your application to create an application session for the user and then redirect them back into your application. The `CallbackData` is defined as follows:


| CallbackData Field | Type | Description |
| ------------------ | ---- | ----------- |
| AccessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| CustomState | Dictionary<string, object>? | If you injected custom state into the Login State Cookie during the Login Endpoint for the current auth request, then that same custom state will be returned in this field. |
| ExpiresAt | long | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `TokenExpirationBuffer` SDK configuration is accounted for in this value. |
| ExpiresIn | int | The duration from the current time until the access token is expired (in seconds). The `TokenExpirationBuffer` SDK configuration is accounted for in this value. |
| IdToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| RefreshToken | string? | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |
| ReturnUrl | string? | The URL to return to after authentication is completed. |
| TenantCustomDomain | string? | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| TenantName | string | The name of the tenant the user belongs to. |
| Userinfo | UserInfo | User information that is retrieved from the [Wristband Userinfo Endpoint](https://docs.wristband.dev/reference/userinfov1) and transformed to user-friendly field names that match the Wristband User entity naming convention. The exact fields that get returned are based on the scopes you configured in the SDK. |

**UserInfo:**

| UserInfo Field | Type | Always Returned | Description |
| -------------- | ---- | --------------- | ----------- |
| UserId | string | Yes | ID of the user. |
| TenantId | string | Yes | ID of the tenant that the user belongs to. |
| ApplicationId | string | Yes | ID of the application that the user belongs to. |
| IdentityProviderName | string | Yes | Name of the identity provider. |
| FullName | string? | No | End-User's full name in displayable form (requires `profile` scope). |
| GivenName | string? | No | Given name(s) or first name(s) of the End-User (requires `profile` scope). |
| FamilyName | string? | No | Surname(s) or last name(s) of the End-User (requires `profile` scope). |
| MiddleName | string? | No | Middle name(s) of the End-User (requires `profile` scope). |
| Nickname | string? | No | Casual name of the End-User (requires `profile` scope). |
| DisplayName | string? | No | Shorthand name by which the End-User wishes to be referred (requires `profile` scope). |
| PictureUrl | string? | No | URL of the End-User's profile picture (requires `profile` scope). |
| Email | string? | No | End-User's preferred email address (requires `email` scope). |
| EmailVerified | bool? | No | True if the End-User's email address has been verified (requires `email` scope). |
| Gender | string? | No | End-User's gender (requires `profile` scope). |
| Birthdate | string? | No | End-User's birthday in YYYY-MM-DD format (requires `profile` scope). |
| TimeZone | string? | No | End-User's time zone (requires `profile` scope). |
| Locale | string? | No | End-User's locale as BCP47 language tag, e.g., "en-US" (requires `profile` scope). |
| PhoneNumber | string? | No | End-User's telephone number in E.164 format (requires `phone` scope). |
| PhoneNumberVerified | bool? | No | True if the End-User's phone number has been verified (requires `phone` scope). |
| UpdatedAt | long? | No | Time the End-User's information was last updated as Unix timestamp (requires `profile` scope). |
| Roles | List<UserInfoRole>? | No | The roles assigned to the user (requires `roles` scope). |
| CustomClaims | Dictionary<string, object>? | No | Object containing any configured custom claims. |

<br>

**UserInfoRole:**

| UserInfoRole Field | Type | Description |
| ------------------ | ---- | ----------- |
| Id | string | Globally unique ID of the role. |
| Name | string | The role name (e.g., "app:app-name:admin"). |
| DisplayName | string | The human-readable display name for the role. |

<br>

#### Redirect Responses

There are certain scenarios where a redirect URL is returned by the SDK. The following are edge cases where this occurs:

- The Login State Cookie is missing by the time Wristband redirects back to the Callback Endpoint.
- The `state` query parameter sent from Wristband to your Callback Endpoint does not match the Login State Cookie.
- Wristband sends an `error` query parameter to your Callback Endpoint, and it is an expected error type that the SDK knows how to resolve.

The location of where the user gets redirected to in these scenarios depends on if the application is using tenant subdomains and if the SDK is able to determine which tenant the user is currently attempting to log in to. The resolution happens in the following order:

1. If the tenant domain can be determined, then the user will get redirected back to your Login Endpoint and ultimately to the Wristband-hosted Tenant-Level Login Page URL.
2. Otherwise, the user will be sent to the Wristband-hosted Application-Level Login Page URL (Tenant Discovery).

<br>

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

For all other error types, the SDK will throw a `WristbandError` object (containing the error and description) that your application can catch and handle. Most errors come from SDK configuration issues during development that should be addressed before release to production.

<br>

### Logout()

```csharp
Task<string> Logout(HttpContext context, LogoutConfig? logoutConfig);
```

| Parameter | Type | Required | Description |
| --------- | ---- | -------- | ----------- |
| context | HttpContext | Yes | The ASP.NET HttpContext object. |
| logoutConfig | LogoutConfig | No | Optional configuration if your application needs custom behavior. |

When users of your application are ready to log out or their application session expires, your frontend should redirect the user to your ASP.NET Logout Endpoint. If your application created a session, it should destroy the session before invoking the `wristbandAuth.Logout()` method.

```sh
GET https://customer01.yourapp.io/auth/logout
```

```csharp
var logoutConfig = new LogoutConfig
{
    RefreshToken = httpContext.GetRefreshToken(),
    TenantName = httpContext.GetTenantName(),
};

// Clear the user's session before completing logout.
httpContext.DestroySession();

var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
return Results.Redirect(wristbandLogoutUrl);
```

This method can also take an optional `LogoutConfig` argument:

| LogoutConfig Field | Type | Required | Description |
| ------------------ | ---- | -------- | ----------- |
| RedirectUrl | string | No | Optional URL that Wristband will redirect to after the logout operation has completed. This will also take precedence over the `CustomApplicationLoginPageUrl` (if specified) in the SDK AuthConfig if the tenant domain cannot be determined when attempting to redirect to the Wristband Logout Endpoint. |
| RefreshToken | string | No | The refresh token to revoke. |
| State | string | No | Optional value that will be appended as a query parameter to the resolved logout URL, if provided. Maximum length of 512 characters. |
| TenantCustomDomain | string | No | The tenant custom domain for the tenant that the user belongs to (if applicable). |
| TenantName | string | No | The name of the tenant the user belongs to. |

#### Which Domains Are Used in the Logout URL?

Wristband supports various tenant domain configurations, including subdomains and custom domains. The SDK automatically determines the appropriate domain configuration when constructing the Wristband Logout URL, which your Logout Endpoint will redirect users to during the logout flow. The selection follows this precedence order:

1. `TenantCustomDomain` in LogoutConfig: If provided, this takes top priority.
2. `TenantName` in LogoutConfig: This takes the next priority if `TenantCustomDomain` is not present.
3. `tenant_custom_domain` query parameter: Evaluated if present and there is also no LogoutConfig provided for either `TenantCustomDomain` or `TenantName`.
4. Tenant subdomain in the URL: Used if none of the above are present, and `ParseTenantFromRootDomain` is specified, and the subdomain is present in the host.
5. `tenant_name` query parameter: Used as the final fallback.

If none of these are specified, the SDK returns the URL for the Application-Level Login (Tenant Discovery) Page.

#### Revoking Refresh Tokens

If your application requested refresh tokens during the Login Workflow (via the `offline_access` scope), it is crucial to revoke the user's access to that refresh token when logging out. Otherwise, the refresh token would still be valid and able to refresh new access tokens.  You should pass the refresh token into the LogoutConfig when invoking the `Logout()` method, and the SDK will call to the [Wristband Revoke Token Endpoint](https://docs.wristband.dev/reference/revokev1) automatically.

#### Resolving Tenant Domains

Much like the Login Endpoint, Wristband requires your application specify a Tenant-Level domain when redirecting to the [Wristband Logout Endpoint](https://docs.wristband.dev/reference/logoutv1). If your application does not utilize tenant subdomains, then you will need to explicitly pass it into the LogoutConfig:

```csharp
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09",
    TenantName = 'customer01'
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

...or you can alternatively pass the `tenant_name` query parameter in your redirect request to your Logout Endpoint:

```csharp
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_name=customer01"
//
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09"
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

If your application uses tenant subdomains, then passing the `TenantName` field to the LogoutConfig is not required since the SDK will automatically parse the subdomain from the URL as long as the `ParseTenantFromRootDomain` SDK config is set.

#### Tenant Custom Domains

If you have a tenant that relies on a tenant custom domain, then you can either explicitly pass it into the LogoutConfig:

```csharp
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09",
    TenantCustomDomain = "mytenant.com",
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

...or you can alternatively pass the `tenant_custom_domain` query parameter in your redirect request to your Logout Endpoint:

```csharp
//
// Logout Request URL -> "https://yourapp.io/auth/logout?client_id=123&tenant_custom_domain=customer01.com"
//
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09"
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

If your application supports a mixture of tenants that use tenant subdomains and tenant custom domains, then you should consider passing both the tenant names and tenant custom domains (either via LogoutConfig or by query parameters) to ensure all use cases are handled by the SDK.

#### Preserving State After Logout

The `State` field in the `LogoutConfig` allows you to preserve application state through the logout flow.

```csharp
var logoutConfig = new LogoutConfig
{
    RefreshToken = "98yht308hf902hc90wh09",
    TenantName = "customer01",
    State = "user_initiated_logout"
};

var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
return Results.Redirect(wristbandLogoutUrl);
```

The state value gets appended as a query parameter to the Wristband Logout Endpoint URL:

```sh
https://customer01.auth.yourapp.io/api/v1/logout?client_id=123&state=user_initiated_logout
```

After logout completes, Wristband will redirect to your configured redirect URL (either your Login Endpoint by default, or a custom logout redirect URL if configured) with the `state` parameter included:

```sh
https://yourapp.io/auth/login?tenant_name=customer01&state=user_initiated_logout
```

This is useful for tracking logout context, displaying post-logout messages, or handling different logout scenarios. The state value is limited to 512 characters and will be URL-encoded automatically.

#### Custom Logout Redirect URL

Some applications might require the ability to land on a different page besides the Login Page after logging a user out. You can add the `RedirectUrl` field to the LogoutConfig, and doing so will tell Wristband to redirect to that location after it finishes processing the logout request.

```csharp
var logoutConfig = new LogoutConfig
{
    RedirectUrl = "https://custom-logout-landing-location.com",
    RefreshToken = "98yht308hf902hc90wh09",
    TenantName="customer01"
};
var wristbandLogoutUrl = await wristbandAuth.Logout(httpContext, logoutConfig);
```

<br>

### RefreshTokenIfExpired()

```csharp
Task<TokenData?> RefreshTokenIfExpired(string refreshToken, long expiresAt);
```

| Argument | Type | Required | Description |
| -------- | ---- | -------- | ----------- |
| refreshToken | string | Yes | The refresh token used to send to Wristband when access tokens expire in order to receive new tokens. |
| expiresAt | long | Yes | Unix timestamp in milliseconds at which the token expires. |

If your application is using access tokens generated by Wristband either to make API calls to Wristband or to protect other backend APIs, then your application needs to ensure that access tokens don't expire until the user's session ends. You can use the refresh token to generate new access tokens.

```csharp
var tokenData = await wristbandAuth.RefreshTokenIfExpired(
    refreshToken: "98yht308hf902hc90wh09",
    expiresAt: 1710707503788
);
```

If the `RefreshTokenIfExpired()` method finds that your token has not expired yet, it will return `null` as the value, which means your logic can simply continue forward as usual.

The `TokenData` is defined as follows:

| TokenData Field | Type | Description |
| --------------- | ---- | ----------- |
| AccessToken | string | The access token that can be used for accessing Wristband APIs as well as protecting your application's backend APIs. |
| ExpiresAt | long | The absolute expiration time of the access token in milliseconds since the Unix epoch. The `TokenExpirationBuffer` SDK configuration is accounted for in this value. |
| ExpiresIn | int | The duration from the current time until the access token is expired (in seconds). The `TokenExpirationBuffer` SDK configuration is accounted for in this value. |
| IdToken | string | The ID token uniquely identifies the user that is authenticating and contains claim data about the user. |
| RefreshToken | string? | The refresh token that renews expired access tokens with Wristband, maintaining continuous access to services. |

<br>

---

<br>

## Session Management

This SDK uses encrypted cookie-based sessions where session data is stored directly in an encrypted browser cookie rather than on the server.

**Why Cookie-Based Sessions?**

- **Zero infrastructure:** No Redis or database required for session storage
- **Scales effortlessly:** No session state to sync across servers or instances
- **Low latency:** No database lookup on every request; session data arrives with the cookie
- **Edge-compatible:** Works in serverless and containerized environments without extra dependencies

**When NOT to Use Cookie-Based Sessions?**

Consider server-side sessions (e.g., Redis, database) if you need:

- **Large session data (>3KB):** Browser cookies are limited to 4KB total. After encryption overhead, you have roughly 3KB for actual session data. If you need more, store a reference ID in the session and fetch the full data from your database.
- **Instant cross-device logout:** Cookie-based sessions can't be invalidated server-side. If an admin needs to immediately revoke all of a user's sessions, you'll need a server-side session store.

**How It Works**

Sessions are built on top of ASP.NET Core's cookie authentication scheme configured in [Set Up Session Management](#2-set-up-session-management), leveraging .NET's built-in cookie encryption. Session data is stored as claims on `HttpContext.User` and automatically persisted to the encrypted cookie by `UseWristbandSessionMiddleware()` after each request completes. No backend session store is required.

For more on .NET's cookie authentication, see the [official ASP.NET Core cookie authentication documentation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie).

<br>

### Session Configuration

Session behavior is configured when adding cookie authentication in `Program.cs`. The SDK provides recommended defaults via `UseWristbandSessionConfig()`, but you can override specific settings to fit your application's needs:

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Wristband.AspNet.Auth;

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.UseWristbandSessionConfig(); // Apply Wristband defaults

        // Override specific settings as needed
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Custom expiration
        options.Cookie.Name = "my_session"; // Custom cookie name
    });
```

The following defaults are applied by `UseWristbandSessionConfig()`:

| Option | Default | Description |
| ------ | ------- | ----------- |
| Cookie.Name | `session` | The name of the session cookie |
| Cookie.HttpOnly | `true` | Prevents JavaScript access to the cookie. **DO NOT OVERRIDE!** |
| Cookie.SecurePolicy | `CookieSecurePolicy.Always` | Cookie only sent over HTTPS. |
| Cookie.SameSite | `SameSiteMode.Lax` | Provides CSRF protection for most scenarios |
| Cookie.Path | `"/"` | Cookie is sent on all paths |
| SlidingExpiration | `true` | Session extends on each request (rolling sessions) |
| ExpireTimeSpan | 1 hour | Session expires after 1 hour of inactivity |
| OnRedirectToLogin | 401 | Returns `401 Unauthorized` instead of redirecting to a login page |
| OnRedirectToAccessDenied | 403 | Returns `403 Forbidden` instead of redirecting to an access denied page |

> **💡 Why `ExpireTimeSpan`?**
>
> `ExpireTimeSpan` is the ASP.NET-recommended way to control session lifetime because it works in conjunction with `SlidingExpiration` to implement rolling sessions. Setting `Max-Age` or `Expires` directly on the cookie bypasses the sliding expiration behavior, and can also cause time drift issues with Wristband's CSRF protection if the cookie expiration gets out of sync with the session expiration.

<br>

### The Session Structure

Once authentication is configured, every request has session data accessible via `HttpContext`. Under the hood, session data is stored as claims on `HttpContext.User` (a `ClaimsPrincipal`), which is the standard .NET behavior for cookie authentication. The SDK provides extension methods that abstract over these claims, giving you a cleaner API for both reading and modifying session data.

> **⚠️ Important:**
>
> When using `UseWristbandSessionMiddleware()`, **always** use the SDK's session extension methods (`SetSessionClaim()`, `RemoveSessionClaim()`, `CreateSessionFromCallback()`, `DestroySession()`) to modify session data. The middleware relies on flags set by these methods to call `SignInAsync`/`SignOutAsync` as the response is starting. Modifying session data directly will result in changes being silently lost.

#### Base Session Fields

These fields are automatically populated when you call `httpContext.CreateSessionFromCallback()` after successful Wristband authentication:

| Session Field | Type | Description |
| ------------- | ---- | ----------- |
| isAuthenticated | bool | Whether the user is authenticated (always `true` after callback). |
| accessToken | string | JWT access token for making authenticated API calls. |
| expiresAt | long | Token expiration timestamp (milliseconds since Unix epoch). |
| userId | string | Unique identifier for the authenticated user. |
| tenantId | string | Unique identifier for the tenant. |
| tenantName | string | Name of the tenant. |
| identityProviderName | string | Name of the identity provider. |
| refreshToken | string (optional) | Refresh token for obtaining new access tokens. Only present if `offline_access` scope was requested. |
| tenantCustomDomain | string (optional) | Custom domain for the tenant, if configured. |

<br>

### Session API

#### CreateSessionFromCallback()

```csharp
void CreateSessionFromCallback(CallbackData callbackData, IEnumerable<Claim>? customClaims);
```

Creates a session from Wristband callback data after successful authentication. This is a convenience method that automatically extracts core user and tenant info from the callback data and marks the session for persistence.

```csharp
// Basic usage
var callbackResult = await wristbandAuth.Callback(httpContext);
httpContext.CreateSessionFromCallback(callbackResult.CallbackData!);

// With custom claims
httpContext.CreateSessionFromCallback(
    callbackResult.CallbackData,
    customClaims: new[]
    {
        new Claim("roles", "admin"),
        new Claim("email", userinfo.Email)
    }
);
```

#### CreateSession()

```csharp
void CreateSession(IEnumerable<Claim> claims);
```

Creates a new session with the provided claims. This is the lower-level method for cases where you need full control over what claims are in the session. For most use cases, prefer `CreateSessionFromCallback()` instead, which automatically extracts core user and tenant info from the callback data.

```csharp
var claims = new List<Claim>
{
    new Claim("userId", userId),
    new Claim("accessToken", token),
    // ... other claims
};

httpContext.CreateSession(claims);
```

#### DestroySession()

```csharp
void DestroySession();
```

Marks the session for destruction. The session will be destroyed by the session middleware after the endpoint completes.

```csharp
httpContext.DestroySession();
// Session will be destroyed after endpoint completes
```

#### SetSessionClaim()

```csharp
void SetSessionClaim(string key, string value);
```

Use `SetSessionClaim()` to add or update session claims. All claims are stored as string types. If the claim already exists it will be overwritten, and if it doesn't exist it will be added. Updates are automatically saved to the encrypted cookie by the `UseWristbandSessionMiddleware()` after your endpoint completes.

```csharp
httpContext.SetSessionClaim("email", "user@example.com");
httpContext.SetSessionClaim("theme", "dark");
httpContext.SetSessionClaim("theme", "light"); // Overwrites "dark" with "light"
httpContext.SetSessionClaim("lastLogin", DateTime.UtcNow.ToString("o"));

// Changes are automatically persisted to the encrypted cookie by the session middleware
```

> **⚠️ Note:** Throws `InvalidOperationException` if the user does not have an active, authenticated session.

#### RemoveSessionClaim()

```csharp
void RemoveSessionClaim(string key);
```

Use `RemoveSessionClaim()` to remove a claim from the session. If the claim doesn't exist, this is a no-op. Removals are automatically saved to the encrypted cookie by the `UseWristbandSessionMiddleware()` after your endpoint completes.

```csharp
httpContext.RemoveSessionClaim("theme");

// Changes are automatically persisted to the encrypted cookie by the session middleware
```

> **⚠️ Note:** Throws `InvalidOperationException` if the user does not have an active, authenticated session.

#### GetSessionClaim()

```csharp
string? GetSessionClaim(string key);
```

Gets a session claim value as a string. Returns `null` if the claim doesn't exist.

```csharp
// Generic getter for any claim - returns null if not present
var theme = httpContext.GetSessionClaim("theme");
var email = httpContext.GetSessionClaim("email") ?? "unknown@example.com";
```

#### Typed Getters

The SDK provides typed extension methods for accessing known Wristband base session fields. All return `null` if the claim is not present (except for `GetRoles()` which returns an empty list):

| Method | Return Type | Description |
| ------ | ----------- | ----------- |
| `IsAuthenticated()` | `bool` | Whether the user has an active authenticated session. Returns `false` if not authenticated |
| `GetUserId()` | `string?` | The authenticated user's ID |
| `GetTenantId()` | `string?` | The tenant ID |
| `GetTenantName()` | `string?` | The tenant name |
| `GetAccessToken()` | `string?` | The access token |
| `GetRefreshToken()` | `string?` | The refresh token. `null` if `offline_access` scope was not requested |
| `GetExpiresAt()` | `long?` | Token expiration as milliseconds since Unix epoch |
| `GetIdentityProviderName()` | `string?` | The identity provider name |
| `GetTenantCustomDomain()` | `string?` | The tenant custom domain. `null` if no custom domain configured |
| `GetRoles()` | `List<UserInfoRole>` | The user's roles. Returns an empty list if the `roles` scope is not configured or no roles are assigned. Parses the JSON-encoded `roles` claim for you.<br><br> **Note:** Roles are not a base session field. You need to explicitly add them as a custom claim in your session for this to return data. |

```csharp
// Check authentication status - returns false if not authenticated
if (httpContext.IsAuthenticated())
{
    // Typed getters for base session fields - return null if not present
    var userId = httpContext.GetUserId();
    var tenantId = httpContext.GetTenantId();
    var tenantName = httpContext.GetTenantName();
    var accessToken = httpContext.GetAccessToken();
    var refreshToken = httpContext.GetRefreshToken(); // null if offline_access scope not requested
    var expiresAt = httpContext.GetExpiresAt();
    var idpName = httpContext.GetIdentityProviderName();
    var customDomain = httpContext.GetTenantCustomDomain(); // null if no custom domain configured
}

// Convenience getter for roles - parses the JSON-encoded roles claim for you.
// Returns an empty list if the roles scope is not configured or no roles are assigned.
var roles = httpContext.GetRoles();
```

#### GetSessionResponse()

```csharp
SessionResponse GetSessionResponse(object? metadata);
```

Creates a `SessionResponse` for Wristband frontend SDKs. Returns user and tenant IDs with optional custom metadata. This is typically used in your Session Endpoint.

> **💡 Note:**
>
> This method automatically sets `Cache-Control: no-store` and `Pragma: no-cache` headers on the response.

| SessionResponse Field | Serializes As | Type | Description |
| --------------------- | ------------- | ---- | ----------- |
| `UserId` | `userId` | `string` | The authenticated user's ID |
| `TenantId` | `tenantId` | `string` | The tenant ID |
| `Metadata` | `metadata` | `object?` | Optional custom metadata. Can contain any JSON-serializable data |

```csharp
app.MapGet("/auth/session", (HttpContext httpContext) =>
{
    var response = httpContext.GetSessionResponse(metadata: new
    {
        email = httpContext.GetSessionClaim("email"),
        fullName = httpContext.GetSessionClaim("fullName")
    });
    
    return Results.Ok(response);
})
.RequireWristbandSession();
```

#### GetTokenResponse()

```csharp
TokenResponse GetTokenResponse();
```

Creates a `TokenResponse` for Wristband frontend SDKs. Returns the access token and its expiration time. This is typically used in your Token Endpoint.

> **💡 Note:**
>
> This method automatically sets `Cache-Control: no-store` and `Pragma: no-cache` headers on the response.

| TokenResponse Field | Serializes As | Type | Description |
| ------------------- | ------------- | ---- | ----------- |
| `AccessToken` | `accessToken` | `string` | The access token for making authenticated API requests |
| `ExpiresAt` | `expiresAt` | `long` | The absolute expiration time of the access token in milliseconds since Unix epoch |

```csharp
app.MapGet("/auth/token", (HttpContext httpContext) =>
{
    var response = httpContext.GetTokenResponse();
    return Results.Ok(response);
})
.RequireWristbandSession();
```

<br>

### CSRF Protection

CSRF (Cross-Site Request Forgery) protection helps prevent unauthorized actions by validating that requests originate from your application's frontend. The SDK implements the [Synchronizer Token Pattern](https://docs.wristband.dev/docs/csrf-protection-for-backend-servers) using a dual-cookie approach.

> **💡 Why not ASP.NET's built-in `IAntiforgery`?**
>
> ASP.NET Core includes built-in CSRF protection via `IAntiforgery`, but it was designed for server-rendered MVC applications (Razor Pages/Views). It doesn't work well with modern SPA frontends or minimal APIs because it expects to manage tokens through HTML form rendering and requires server-side session state (`ISession`). Since this SDK is built around encrypted cookie-based sessions with no backend session store, we provide our own CSRF implementation.

#### Enabling CSRF Protection

Add CSRF protection configuration in `Program.cs`:

```csharp
// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

// Enable CSRF protection with defaults
builder.Services.AddWristbandCsrfProtection();
```

If you need to customize the defaults, you can pass options:

```csharp
builder.Services.AddWristbandCsrfProtection(options =>
{
    options.CsrfHeaderName = "MY-CSRF-HEADER"; // Default: "X-CSRF-TOKEN"
    options.CsrfCookieName = "MY-CSRF-COOKIE"; // Default: "CSRF-TOKEN"
    options.CsrfCookieDomain = ".example.com"; // Default: null (same domain only). Set to share across subdomains.
});
```

**Configuration Options:**

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| EnableCsrfProtection | bool | `true` | Enable CSRF token validation. Set automatically to `true` when using `AddWristbandCsrfProtection()`. |
| CsrfHeaderName | string | `X-CSRF-TOKEN` | The HTTP request header name to read the CSRF token from. |
| CsrfCookieName | string | `CSRF-TOKEN` | Name of the CSRF cookie. |
| CsrfCookieDomain | string | null | Domain for CSRF cookie. Falls back to the `Cookie.Domain` value set in `AddCookie()` if not specified. |

#### How It Works

When you create a session using `CreateSessionFromCallback()` and CSRF protection is enabled, the SDK:

1. **Generates a CSRF token** - A cryptographically secure random token
2. **Stores the token in two places:**
   - **Session cookie** (encrypted, HttpOnly) - Contains the CSRF token as part of the encrypted session data
   - **CSRF cookie** (unencrypted, readable by JavaScript) - Contains the same CSRF token in plaintext

This dual-cookie approach ensures:
- The session cookie proves the user is authenticated (server-side validation)
- The CSRF cookie must be read by your frontend and sent in request headers (client-side participation)
- An attacker cannot forge requests because they cannot read cookies from your domain due to the browser's Same-Origin Policy

#### Frontend Implementation

Your frontend must read the CSRF token from the CSRF cookie and include it in the configured header for all state-changing requests:

```typescript
// Read CSRF token from cookie
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('CSRF-TOKEN='))
  ?.split('=')[1];

// Include in requests
fetch('/api/protected-endpoint', {
  method: 'POST',
  headers: {
    'X-CSRF-TOKEN': csrfToken,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ data: 'example' })
});
```

#### Automatic Validation

When you use `RequireWristbandSession()` and CSRF protection is enabled, CSRF validation happens automatically on every request. If validation fails, a `403 Forbidden` response is returned.

```csharp
app.MapPost("/api/data", (HttpContext httpContext) =>
{
    // By the time your handler runs, CSRF has been validated
    httpContext.SetSessionClaim("data", "new_data");
    return Results.Ok(new { status = "success" });
})
.RequireWristbandSession(); // CSRF automatically validated
```

> **💡 SameSite Cookie Protection**
>
> If you're using the default `SameSite=Lax` (or `SameSite=Strict`), you already have some protection in place and may not need to enable CSRF tokens. Enable CSRF protection if you're using `SameSite=None` or you want defense-in-depth security.

<br>

### Session Encryption Configuration

Session encryption is configured using `AddInMemoryKeyDataProtection()`, which overrides ASP.NET Core's default Data Protection behavior to derive encryption keys from a shared secret. This enables sessions to work across all deployment types (single-server, multi-server, Kubernetes, serverless, etc.) without requiring Redis, databases, or persistent storage.

This SDK configuration uses industry-standard cryptographic algorithms: HKDF-SHA256 for key derivation (RFC 5869), AES-256-GCM for authenticated encryption providing confidentiality, integrity, and authenticity, purpose isolation so different features (cookies, CSRF, anti-forgery) derive independent keys, timestamp validation to detect future-dated cookies (prevents clock skew attacks), and a version byte to enable future format compatibility.

> **💡 Alternative: Persistent Key Storage**
>
> If you need to use ASP.NET's default Data Protection with persistent storage backends (Redis, Azure Blob Storage, file shares), see [Session Encryption with Persistent Key Storage](#session-encryption-with-persistent-key-storage) in the Advanced Configuration section.

#### Basic Configuration

The session encryption secret is typically loaded from environment variables or secure configuration:

```csharp
using Wristband.AspNet.Auth;

builder.Services.AddWristbandAuth(options => { /* ... */ });

// Configure session encryption with a shared secret
builder.Services.AddInMemoryKeyDataProtection(
    builder.Configuration["SESSION_ENCRYPTION_KEY"]!
);
```

#### Generating Secrets

Generate a secure 32+ character secret and store it in your environment configuration (Kubernetes Secrets, Azure App Settings, AWS Secrets Manager, etc.):

```bash
# Example: Using openssl (Linux/macOS)
openssl rand -base64 32
```

#### Secret Rotation

Zero-downtime secret rotation is supported by providing up to 3 secrets. The first secret encrypts new sessions, while all secrets can decrypt existing sessions:

```csharp
// Parse comma-separated secrets from configuration
var secrets = builder.Configuration["SESSION_ENCRYPTION_KEY"]!.Split(',');
builder.Services.AddInMemoryKeyDataProtection(secrets);
```

**Rotation workflow:**

1. **Add new secret alongside old:**
```bash
   # New secret first, old secret second
   SESSION_ENCRYPTION_KEY=new-secret-here,old-secret-here
```

2. **Deploy to all instances** - Both secrets work simultaneously

3. **Wait for old sessions to expire** - Default session expiration is 1 hour

4. **Remove old secret:**
```bash
   # Keep only new secret
   SESSION_ENCRYPTION_KEY=new-secret-here
```

Sessions encrypted with the old secret are automatically re-encrypted with the new secret on the user's next request.

<br>

---

<br>

## Authorization Policies

ASP.NET Core's authorization system works by attaching [authorization policies](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policy) to endpoints or route groups. When a request hits a protected endpoint, the [authorization middleware](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/overview) evaluates the policy's requirements and either allows or rejects the request.

The Wristband SDK builds on this system by providing pre-built authorization policies tailored for Wristband authentication. These policies handle the specifics of validating sessions, refreshing tokens, and validating CSRF tokens within .NET's standard authorization pipeline. You can use session-based authentication, JWT bearer tokens, or combine both strategies for multi-strategy authentication.

> **⚠️ Important:**
>
> Any setup that uses Wristband session authentication **must** set `CookieAuthenticationDefaults.AuthenticationScheme` as the default scheme via `AddAuthentication()`. This ensures .NET automatically populates `HttpContext.User` from the session cookie on every request, including unprotected endpoints, so that session data is always accessible. Without this, session data will only be available on endpoints that explicitly require authentication.

<br>

### Session-Based Authentication

Session-based authentication validates users via encrypted session cookies. Use this for traditional web applications where users log in through your application's UI.

> **💡 Default Authentication Scheme**
>
> `CookieAuthenticationDefaults.AuthenticationScheme` is set as the default scheme here. This ensures .NET automatically populates `HttpContext.User` from the session cookie on all requests, including unprotected endpoints - so session data is always available.

#### Setup

Register the Wristband authorization handler and policies in `Program.cs`. `AddWristbandDefaultPolicies()` registers both the `"WristbandSession"` and `"WristbandJwt"` policies:

```csharp
// Program.cs
using Microsoft.AspNetCore.Authentication.Cookies;
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

// Add Wristband auth service
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "<your-client-id>";
    options.ClientSecret = "<your-client-secret>";
    options.WristbandApplicationVanityDomain = "<your-wristband-application-vanity-domain>";
});

// Add authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => options.UseWristbandSessionConfig());

// Register the Wristband authorization handler (required for all Wristband policies)
builder.Services.AddWristbandAuthorizationHandler();

// Add authorization policies
builder.Services.AddAuthorization(options => options.AddWristbandDefaultPolicies());

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseWristbandSessionMiddleware();

app.Run();
```

#### Using the Session Policy

Apply the session policy at the endpoint or route group level by using the `RequireWristbandSession()` extension method:

**Endpoint-Level Protection:**
```csharp
// Protect individual endpoints
app.MapGet("/api/profile", (HttpContext httpContext) =>
{
    var userId = httpContext.GetUserId();
    var email = httpContext.GetSessionClaim("email");
    
    return Results.Ok(new { userId, email });
})
.RequireWristbandSession();
```

**Route Group Protection:**
```csharp
// Protect entire route groups
var protectedRoutes = app.MapGroup("/api/protected");
protectedRoutes.RequireWristbandSession();

protectedRoutes.MapGet("/users", (HttpContext httpContext) =>
{
    // All routes in this group require session auth
    return Results.Ok(new { users = new[] { "user1", "user2" } });
});

protectedRoutes.MapPost("/orders", (HttpContext httpContext) =>
{
    var userId = httpContext.GetUserId();
    // Process order...
    return Results.Ok(new { status = "created" });
});
```

#### What the Session Policy Does

When a request hits an endpoint protected with `RequireWristbandSession()`, the authorization handler:

1. **Validates the session** - Checks that the session cookie exists and is valid
2. **Validates CSRF tokens** - If CSRF protection is enabled, checks that the CSRF token in the request header matches the session token
3. **Refreshes expired tokens** - If `refreshToken` and `expiresAt` are present, automatically refreshes the access token when expired (with up to 3 retry attempts)
4. **Updates the session** - Saves new token data if refresh occurred
5. **Extends session expiration** - Implements rolling sessions via the session middleware

If any validation fails, the request is rejected with a `401 Unauthorized` (authentication failure) or `403 Forbidden` (CSRF failure) response if CSRF protection is enabled.

#### Handling Auth Errors in Your Frontend

Your frontend should treat 401 and 403 responses as signals that the user must re-authenticate before continuing.

```typescript
async function makeAuthenticatedRequest(url: string, options: RequestInit = {}) {
  try {
    const response = await fetch(url, {
      ...options,
      credentials: 'include', // Include cookies
      headers: {
        'X-CSRF-TOKEN': getCsrfToken(), // Your function to read CSRF cookie
        ...options.headers,
      },
    });

    // Handle authentication errors
    if (response.status === 401 || response.status === 403) {
      // Redirect to login - user needs to re-authenticate
      window.location.href = '/api/auth/login';
      return;
    }

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Request failed:', error);
    throw error;
  }
}
```

<br>

### JWT Bearer Token Authentication

JWT authentication validates users via Bearer tokens in the `Authorization` header. Use this for API-first applications, mobile apps, or when your frontend stores access tokens client-side.

The JWT Bearer authentication here relies on the [aspnet-jwt SDK](https://github.com/wristband-dev/aspnet-jwt) under the hood, which is a dependency of this auth SDK.

ASP.NET Core's built-in `AddJwtBearer()` registers a handler that extracts Bearer tokens from the `Authorization` header and validates them. `UseWristbandJwksValidation()` is re-exported from the aspnet-jwt SDK and plugs Wristband's JWKS-based signature verification, key caching, and key rotation into that handler as its validation logic.

#### Setup

Register the Wristband authorization handler and policies in `Program.cs`. `AddWristbandDefaultPolicies()` registers both the `"WristbandSession"` and `"WristbandJwt"` policies. Use the `UseWristbandJwksValidation()` extension method to register JWT Bearer authentication with Wristband JWKS validation:

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

// Add Wristband auth service
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "<your-client-id>";
    options.ClientSecret = "<your-client-secret>";
    options.WristbandApplicationVanityDomain = "<your-wristband-application-vanity-domain>";
});

// Add JWT Bearer authentication with Wristband JWKS validation
builder.Services.AddAuthentication()
    .AddJwtBearer(options => options.UseWristbandJwksValidation(
        wristbandApplicationVanityDomain: "invotastic.us.wristband.dev",
        jwksCacheMaxSize: 20,  // Optional
        jwksCacheTtl: TimeSpan.FromHours(1)  // Optional
    ));

// Register the Wristband authorization handler (required for all Wristband policies)
builder.Services.AddWristbandAuthorizationHandler();

// Add authorization policies
builder.Services.AddAuthorization(options => options.AddWristbandDefaultPolicies());

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// No Session Middleware needed if only using JWT authentication

app.Run();
```

**Configuration Options:**

| Parameter | Type | Required | Default | Description |
| --------- | ---- | -------- | ------- | ----------- |
| wristbandApplicationVanityDomain | string | Yes | _N/A_ | The vanity domain of your Wristband application. This is used to locate and fetch the JWKS signing keys for validating incoming JWTs. |
| jwksCacheMaxSize | int | No | 20 | Maximum number of JSON Web Keys (JWKs) to cache in memory. Uses LRU (Least Recently Used) eviction. The default is sufficient for most cases. |
| jwksCacheTtl | `TimeSpan` | No | null (infinite) | How long JWKs stay cached before refresh. The default is sufficient for most cases. Example: `TimeSpan.FromHours(1)` for a 1 hour cache TTL. |

#### Using the JWT Policy

Apply the JWT policy at the endpoint or route group level via the `RequireWristbandJwt` extension method:

**Endpoint-Level Protection:**
```csharp
// Protect individual endpoints
app.MapGet("/api/orders", (HttpContext httpContext) =>
{
    var payload = httpContext.GetJwtPayload();
    var userId = payload.Sub;
    var tenantId = payload.Claims?["tnt_id"];
    
    return Results.Ok(new { userId, tenantId });
})
.RequireWristbandJwt();
```

**Route Group Protection:**
```csharp
// Protect entire route groups
var apiRoutes = app.MapGroup("/api");
apiRoutes.RequireWristbandJwt();

apiRoutes.MapGet("/users", (HttpContext httpContext) =>
{
    var payload = httpContext.GetJwtPayload();
    return Results.Ok(new { users = new[] { "user1", "user2" } });
});

apiRoutes.MapPost("/orders", (HttpContext httpContext) =>
{
    var userId = httpContext.GetJwtPayload().Sub;
    return Results.Ok(new { status = "created" });
});
```

#### What the JWT Policy Does

When a request hits an endpoint protected with `RequireWristbandJwt()`, the authorization handler:

1. **Extracts the JWT** - Gets the token from the `Authorization: Bearer <token>` header
2. **Verifies the signature** - Uses cached JWKS from Wristband to validate the token signature
3. **Validates claims** - Checks expiration, issuer, audience, and other standard JWT claims
4. **Populates HttpContext** - Stores the validated JWT and payload on the HttpContext, which is what makes `GetJwt()` and `GetJwtPayload()` work in your endpoint handlers

If validation fails, the request is rejected with a `401 Unauthorized` response.

#### Accessing JWT Data

The SDK provides extension methods for accessing JWT data from authenticated requests. These are re-exported from the aspnet-jwt package, so you only need `using Wristband.AspNet.Auth;`:

| Method | Return Type | Description |
| ------ | ----------- | ----------- |
| `GetJwt()` | `string?` | The raw JWT token from the `Authorization` header. `null` if not present. |
| `GetJwtPayload()` | `JWTPayload` | The validated JWT payload, populated after successful authentication. |

The `JWTPayload` object contains the following:

| Property | Type | Description |
| -------- | ---- | ----------- |
| `Sub` | `string?` | The user ID (sub claim) |
| `Iss` | `string?` | The issuer (iss claim) |
| `Aud` | `string[]?` | The audience (aud claim) |
| `Exp` | `long?` | Expiration time as Unix timestamp in seconds |
| `Iat` | `long?` | Issued-at time as Unix timestamp in seconds |
| `Nbf` | `long?` | Not-before time as Unix timestamp in seconds |
| `Jti` | `string?` | The JWT ID (jti claim) |
| `Claims` | `Dictionary<string, string>?` | All claims as a dictionary, including standard and custom Wristband claims (e.g., `tnt_id`, `app_id`) |

```csharp
app.MapGet("/api/profile", (HttpContext httpContext) =>
{
    // Get the raw JWT token
    var jwt = httpContext.GetJwt();
    
    // Get the validated JWT payload
    var payload = httpContext.GetJwtPayload();

    // Standard claims
    var userId = payload.Sub;
    var issuer = payload.Iss;
    var expiration = payload.Exp;

    // Custom Wristband claims
    var tenantId = payload.Claims?["tnt_id"];
    var appId = payload.Claims?["app_id"];
    
    return Results.Ok(new { userId, tenantId, appId });
})
.RequireWristbandJwt();
```

<br>

### Multi-Strategy Authentication

Most applications only need one authentication strategy: either session-based auth for web apps or JWT for stateless APIs. Multi-strategy authentication is for when your application needs to serve both at the same time. A common example is a web application that has browser-based users logging in with sessions, but also exposes API endpoints that external services or mobile clients hit with Bearer tokens. Rather than duplicating your endpoint logic into separate session-only and JWT-only routes, multi-strategy lets a single endpoint accept either method.

`AddWristbandDefaultPolicies()` registers both the Session and JWT policies separately (`"WristbandSession"` and `"WristbandJwt"`), and you pick one per endpoint using `RequireWristbandSession()` or `RequireWristbandJwt()`. Multi-strategy is different since `AddWristbandMultiStrategyPolicy()` registers a single policy called `"WristbandMultiAuth"`, which is what `RequireWristbandMultiAuth()` enforces. Instead of picking one strategy per endpoint, that policy tries each strategy in the order you specify until one succeeds.

#### Setup

Register both authentication schemes and a multi-strategy policy:

```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

// Add Wristband auth service
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = "<your-client-id>";
    options.ClientSecret = "<your-client-secret>";
    options.WristbandApplicationVanityDomain = "<your-wristband-application-vanity-domain>";
});

// Add both authentication schemes. Cookie is the default scheme so that
// session data is available on unprotected endpoints (e.g. logout).
// Protected endpoints override this via their authorization policies.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => options.UseWristbandSessionConfig())
    .AddJwtBearer(options => options.UseWristbandJwksValidation(
        wristbandApplicationVanityDomain: "invotastic.us.wristband.dev"
    ));

// Register the Wristband authorization handler (required for all Wristband policies)
builder.Services.AddWristbandAuthorizationHandler();

// Add authorization policies
builder.Services.AddAuthorization(options =>
{
    // Add "WristbandMultiAuth" policy: try Session first, fall back to JWT.
    // Endpoints using RequireWristbandMultiAuth() will accept either.
    options.AddWristbandMultiStrategyPolicy([AuthStrategy.Session, AuthStrategy.Jwt]);
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.UseWristbandSessionMiddleware();

app.Run();
```

#### Strategy Order

Strategies are tried in the order you specify. The first strategy that successfully authenticates the request is used:

```csharp
// Try SESSION first, fall back to JWT for API clients
options.AddWristbandMultiStrategyPolicy([AuthStrategy.Session, AuthStrategy.Jwt]);

// Or try JWT first, fall back to SESSION
options.AddWristbandMultiStrategyPolicy([AuthStrategy.Jwt, AuthStrategy.Session]);
```

#### Using the Multi-Strategy Policy

Apply the multi-strategy policy at the endpoint or route group level via the `RequireWristbandMultiAuth()` extension method. You can check `HttpContext.User.Identity?.AuthenticationType` against the scheme constants to see which auth strategy succeeded:

- `CookieAuthenticationDefaults.AuthenticationScheme` for session authentication
- `JwtBearerDefaults.AuthenticationScheme` for JWT authentication

**Endpoint-Level Protection:**
```csharp
app.MapGet("/api/data", (HttpContext httpContext) =>
{
    var authType = httpContext.User.Identity?.AuthenticationType;

    if (authType == CookieAuthenticationDefaults.AuthenticationScheme)
    {
        var userId = httpContext.GetUserId();
        return Results.Ok(new { data = $"Session user: {userId}" });
    }
    else if (authType == JwtBearerDefaults.AuthenticationScheme)
    {
        var userId = httpContext.GetJwtPayload().Sub;
        return Results.Ok(new { data = $"JWT user: {userId}" });
    }

    return Results.Unauthorized();
})
.RequireWristbandMultiAuth();
```

**Route Group Protection:**
```csharp
// Protect entire route groups
var mixedRoutes = app.MapGroup("/api/mixed");
mixedRoutes.RequireWristbandMultiAuth();

mixedRoutes.MapGet("/users", (HttpContext httpContext) =>
{
    // Handles both session and JWT auth
    return Results.Ok(new { users = new[] { "user1", "user2" } });
});
```

#### What the Multi-Strategy Policy Does

When a request hits an endpoint protected with `RequireWristbandMultiAuth()`, the authorization handler:

1. **Tries the first strategy** (e.g., SESSION) - Validates session cookie and refreshes tokens if needed
2. **If first strategy fails, tries the second** (e.g., JWT) - Validates JWT bearer token
3. **Returns success** - If any strategy succeeds
4. **Returns error response** - If all strategies fail

The `RequireWristbandMultiAuth()` policy can result in the following responses:

| Response | Condition |
| -------- | --------- |
| `ArgumentException` | Thrown at startup if the strategies array passed to `AddWristbandMultiStrategyPolicy()` is empty or contains duplicates. |
| `401 Unauthorized` | If all authentication strategies fail. |
| `403 Forbidden` | If CSRF validation fails (when using session auth with CSRF protection enabled). |

<br>

#### Custom Policy Names

By default, `AddWristbandMultiStrategyPolicy()` registers the policy under the name `"WristbandMultiAuth"`, which is what `RequireWristbandMultiAuth()` enforces. If you need multiple multi-strategy policies with different strategy orders, pass a custom `policyName` when registering policies:

```csharp
options.AddWristbandMultiStrategyPolicy(
    [AuthStrategy.Session, AuthStrategy.Jwt],
    "SessionFirst"
);

options.AddWristbandMultiStrategyPolicy(
    [AuthStrategy.Jwt, AuthStrategy.Session],
    "JwtFirst"
);
```

Then use `.RequireAuthorization()` with that name directly:

```csharp
app.MapGet("/api/session-first", () => "Hello")
    .RequireAuthorization("SessionFirst");

app.MapGet("/api/jwt-first", () => "Hello")
    .RequireAuthorization("JwtFirst");

// Combine with other policies — all must be satisfied
app.MapGet("/api/admin", () => "Admin only")
    .RequireAuthorization("SessionFirst", "AdminOnly");
```

<br>

---

<br>

## Advanced Configuration

### Configuration Sources

The examples in this README show configuration values inline for simplicity. In practice, you should load these values from secure sources.

#### From Configuration Files

**Best for:** Storing non-secret settings and environment-specific configurations.

Load settings from `appsettings.json` or other configuration files:

**appsettings.json:**
```json
{
  "WristbandAuthConfig": {
    "ClientId": "<your-client-id>",
    "ClientSecret": "<your-client-secret>",
    "WristbandApplicationVanityDomain": "<your-wristband-application-vanity-domain>"
  }
}
```

```csharp
// Program.cs
builder.Services.AddWristbandAuth(options =>
{
    var config = builder.Configuration.GetSection("WristbandAuthConfig");
    options.ClientId = config["ClientId"];
    options.ClientSecret = config["ClientSecret"];
    options.WristbandApplicationVanityDomain = config["WristbandApplicationVanityDomain"];
});
```

> **⚠️ Security Warning:**
>
> Never commit secrets to source control. Store only non-sensitive values like `ClientId` and `WristbandApplicationVanityDomain` in `appsettings.json`. Use one of the methods below for the `ClientSecret`.

<br>

#### From Environment Variables

**Best for:** Cloud deployments, CI/CD pipelines, and containerized applications.

Environment variables are widely supported across hosting platforms and keep secrets out of your codebase:

```csharp
// Program.cs
builder.Services.AddWristbandAuth(options =>
{
    options.ClientId = Environment.GetEnvironmentVariable("WRISTBAND_CLIENT_ID");
    options.ClientSecret = Environment.GetEnvironmentVariable("WRISTBAND_CLIENT_SECRET");
    options.WristbandApplicationVanityDomain = Environment.GetEnvironmentVariable("WRISTBAND_DOMAIN");
});
```

Set environment variables in your deployment platform (Azure App Service, AWS, Docker, etc.) or locally:
```bash
export WRISTBAND_CLIENT_ID="your-client-id"
export WRISTBAND_CLIENT_SECRET="your-client-secret"
export WRISTBAND_DOMAIN="your-domain.us.wristband.dev"
```

> **💡 .env Files:**
>
> Unlike Node.js, .NET doesn't read `.env` files by default. For local development, use User Secrets instead. If you prefer `.env` files, consider packages like `dotenv.net`.

<br>

#### User Secrets (Local Development Only)

**Best for:** Local development without exposing secrets in code or configuration files.

.NET User Secrets stores sensitive data outside your project directory, preventing accidental commits to source control:

```bash
dotnet user-secrets init
dotnet user-secrets set "WristbandAuthConfig:ClientId" "your-client-id"
dotnet user-secrets set "WristbandAuthConfig:ClientSecret" "your-client-secret"
dotnet user-secrets set "WristbandAuthConfig:WristbandApplicationVanityDomain" "your-domain.us.wristband.dev"
```

Then load from configuration as shown in the "From Configuration Files" example. User secrets are automatically loaded in the Development environment.

> **💡 Note:**
>
> User secrets are stored in your user profile directory and are only available on your local machine. They are not deployed with your application. 

<br>

#### Cloud Secrets Management (Production)

**Best for:** Production applications requiring centralized secret management, rotation, and access control.

Cloud-based secrets management provides enterprise-grade security features like encryption at rest, audit logging, and automatic secret rotation. These services integrate with your cloud provider's identity and access management (IAM) systems for secure, auditable secret access.

**Example: Azure Key Vault**
```csharp
builder.Configuration.AddAzureKeyVault(
    new Uri("https://your-vault.vault.azure.net/"),
    new DefaultAzureCredential());
```

<br>

### Named Services (Multiple OAuth2 Clients)

If your application needs to support multiple Wristband OAuth2 clients (e.g., different tenant configurations or separate client credentials), you can register named instances of the authentication service.

#### Configuration

Structure your `appsettings.json` with named configurations:

```json
{
  "WristbandAuthConfig": {
    "primary": {
      "ClientId": "primary-client-id",
      "ClientSecret": "primary-secret",
      "WristbandApplicationVanityDomain": "primary.us.wristband.dev"
    },
    "secondary": {
      "ClientId": "secondary-client-id",
      "ClientSecret": "secondary-secret",
      "WristbandApplicationVanityDomain": "secondary.us.wristband.dev"
    }
  }
}
```

Register multiple named services in `Program.cs`:

```csharp
// Program.cs
using Wristband.AspNet.Auth;

var builder = WebApplication.CreateBuilder(args);

// Register primary auth service
builder.Services.AddWristbandAuth("primary", options =>
{
    var config = builder.Configuration.GetSection("WristbandAuthConfig:primary");
    options.ClientId = config["ClientId"];
    options.ClientSecret = config["ClientSecret"];
    options.WristbandApplicationVanityDomain = config["WristbandApplicationVanityDomain"];
});

// Register secondary auth service
builder.Services.AddWristbandAuth("secondary", options =>
{
    var config = builder.Configuration.GetSection("WristbandAuthConfig:secondary");
    options.ClientId = config["ClientId"];
    options.ClientSecret = config["ClientSecret"];
    options.WristbandApplicationVanityDomain = config["WristbandApplicationVanityDomain"];
});

var app = builder.Build();
app.Run();
```

#### Usage in Endpoints

Use the `WristbandAuthServiceFactory` to retrieve the appropriate named service:

```csharp
app.MapGet("/auth/login", async (HttpContext httpContext, WristbandAuthServiceFactory authFactory) =>
{
    // Get the named service
    var wristbandAuth = authFactory.GetService("primary");
    var wristbandAuthorizeUrl = await wristbandAuth.Login(httpContext);
    return Results.Redirect(wristbandAuthorizeUrl);
});

app.MapGet("/auth/callback", async (HttpContext httpContext, WristbandAuthServiceFactory authFactory) =>
{
    var wristbandAuth = authFactory.GetService("primary");
    var callbackResult = await wristbandAuth.Callback(httpContext);
    
    if (callbackResult.Type == CallbackResultType.RedirectRequired)
    {
        return Results.Redirect(callbackResult.RedirectUrl);
    }
    
    httpContext.CreateSessionFromCallback(callbackResult.CallbackData!);
    return Results.Redirect("/home");
});
```

<br>

### Combining Authorization Policies

When using `AddWristbandDefaultPolicies()`, the `RequireWristbandSession()` and `RequireWristbandJwt()` convenience methods only enforce authentication. If your endpoint also requires specific roles, permissions, or other custom policies, use `.RequireAuthorization()` directly and pass multiple policy names:

```csharp
// Session auth + admin role
app.MapGet("/api/admin", () => "Admin only")
    .RequireAuthorization("WristbandSession", "AdminOnly");

// JWT auth + specific permission
app.MapGet("/api/users/edit", () => "Edit users")
    .RequireAuthorization("WristbandJwt", "CanEditUsers");

// Session auth + multiple custom policies
app.MapGet("/api/billing", () => "Billing")
    .RequireAuthorization("WristbandSession", "BillingAccess", "ActiveSubscription");
```

<br>

### Session Encryption with Persistent Key Storage

By default, ASP.NET Core generates and manages encryption keys locally, which works for single-server deployments. For multi-server or containerized deployments (Kubernetes, Docker Swarm, load balancers, etc.), you must configure shared encryption keys across all instances. Otherwise, sessions created on one server cannot be decrypted by another, causing users to be randomly logged out as requests hit different servers.

This SDK's `AddInMemoryKeyDataProtection()` provides zero-infrastructure session encryption (see [Session Encryption Configuration](#session-encryption-configuration)). Alternatively, you can use ASP.NET's Data Protection system with persistent storage backends if you already have infrastructure like Redis or need Data Protection features beyond session cookies (e.g., protecting database fields, files, or custom data).

**Benefits of persistent storage:**
- Keys survive server restarts and are automatically shared across instances
- Microsoft's built-in automatic key rotation and lifecycle management
- Additional Data Protection features beyond session cookies (database fields, files, custom data encryption)
- Centralized audit trail and key management through your storage backend

**Choose persistent storage if:**
- You already have Redis or other persistent storage infrastructure
- You need Data Protection features beyond session cookies (e.g., protecting database fields, files)
- You prefer Microsoft's automatic key management over manual secret rotation

#### Configuration

Use ASP.NET's Data Protection system with a shared key storage backend:

```csharp
// Redis
builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys");

// Azure Blob Storage
builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(blobClient);

// Network file share
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"\\server\share\keys"));
```

See Microsoft's [Configure ASP.NET Core Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview) for all configuration options.

<br>

---

<br>

## Related Wristband SDKs

This SDK builds upon and integrates with other Wristband SDKs to provide a complete authentication solution:

**[@wristband/aspnet-jwt](https://github.com/wristband-dev/aspnet-jwt)**

This SDK leverages the Wristband ASP.NET JWT SDK for JWT validation when using JWT authentication strategies. It handles JWT signature verification, token parsing, and JWKS key management. The JWT SDK functions are also re-exported from this package, allowing you to use them directly for custom JWT validation scenarios beyond the built-in authentication dependencies. Refer to that GitHub repository for more information on JWT validation configuration and options.

**[@wristband/react-client-auth](https://github.com/wristband-dev/react-auth)**

For handling client-side authentication and session management in your React frontend, check out the Wristband React Client Auth SDK. It integrates seamlessly with this backend SDK by consuming the Session and Token endpoints you create. Refer to that GitHub repository for more information on frontend authentication patterns.

<br>

## Wristband Multi-Tenant ASP.NET Demo App

You can check out the [Wristband ASP.NET demo app](https://github.com/wristband-dev/aspnet-demo-app) to see this SDK in action. Refer to that GitHub repository for more information.

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.

<br/>
