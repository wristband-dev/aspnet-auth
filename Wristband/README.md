## Add Wristband to your Asp.Net Core Application

1. Copy the Wristband project into your solution.
2. Add a reference to the Wristband project to your Asp.Net Core API project
3. Setup the Wristband Application and Tenant, as described in `README-Wristband-Developer.md` and `README-Wristband-Production.md`
4. Run something like `openssl rand -base64 32` to create a 32 byte base-64 encoded LoginStateSecret,
   which will be used to secure cookie contents.
5. Place the LoginStateSecret and Wristband client secret in the .NET Secrets file or similar for your API project
```json
{
  "Wristband": {
    "AuthConfig": {
      "ClientSecret": "---your-wristband-client-secret---",
      "LoginStateSecret": "---your-login-secret---"
    }
  }
}
```
6. Add the required nuget packages to your Blazor WebAssembly .csproj:
```xml
        ...
        <PackageReference Include="Microsoft.AspNetCore.Components.Authorization" Version="8.0.10" />
        <PackageReference Include="Microsoft.AspNetCore.WebUtilities" Version="8.0.10" />
        <PackageReference Include="Microsoft.Extensions.Http" Version="8.0.0" />
        ...
```
7. Add the required `using` entries to your `Program.cs`
```csharp
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Wristband;
```
8. Add the required services to your `Program.cs`
```csharp
var services = builder.Services;

services.AddAuthorization();
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie();

services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

services.AddHttpContextAccessor();
services.AddHttpClient();

services.Configure<AuthConfig>(builder.Configuration.GetSection("Wristband:AuthConfig"));
services.Configure<LoginConfig>(builder.Configuration.GetSection("Wristband:LoginConfig"));
services.Configure<LogoutConfig>(builder.Configuration.GetSection("Wristband:LogoutConfig"));
services.AddScoped<IWristbandAuthService>(serviceProvider =>
{
    var authConfig = serviceProvider.GetRequiredService<IOptions<AuthConfig>>().Value;
    var loginConfig = serviceProvider.GetRequiredService<IOptions<LoginConfig>>().Value;
    var logoutConfig = serviceProvider.GetRequiredService<IOptions<LogoutConfig>>().Value;
    var httpClientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();
    return new WristbandAuthService(httpClientFactory, authConfig, loginConfig, logoutConfig);
});

```
9. Configure your `Program.cs` app to use the required middleware (NOTE: The order of middleware is important, UseRouting must come before UseAuthentication and UseAuthorization, which must come before mapping of routes)
```csharp
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseSession();
app.UseMiddleware<WristbandAuthMiddleware>();
app.MapDefaultEndpoints();
app.MapWristbandEndpoints();
```

## Add Wristband to your TypeScript/React/Vite Frontend

1. Copy the 4 wristband files from the `Sample-Wristband-React/clientApp/src` folder into your frontend project
  - `wristbandApiClient.ts`
  - `WristbandAuthProvider.tsx`
  - `WristbandTenantProvider.tsx`
  - `wristbandUtils.ts`

2. Add the following to your `clientApp/src/App.tsx` file:
```tsx
import { WristbandAuthProvider } from "./WristbandAuthProvider";
import { WristbandTenantProvider } from "./WristbandTenantProvider";
...
const disableAuthForTesting = false;
    ...
    <WristbandAuthProvider
        disableAuthForTesting={disableAuthForTesting}
        securing={
            <div className={styles.fullScreen}>
                <p className={styles.centeredText}>Securing...</p>
            </div>
        }
    >
        <WristbandTenantProvider
            tenants={{
                default: { name: "Other", logo: otherLogo },
            }}
        >
            ...
        </WristbandTenantProvider>
    </WristbandAuthProvider>
```

## Add Wristband to your Blazor WebAssembly Frontend

1. Copy the 5 wristband files from the `Sample-Wristband-Blazor/Apps.Blazor` folder into your frontend project
  - `CustomAuthenticationLocalStorageService.cs`
  - `CustomAuthenticationStateProvider.cs`
  - `CustomAuthenticationUser.cs`
  - `RedirectToWristbandLogin.razor`
  - `RedirectToWristbandLogout.razor`

2. In your App.razor file, wrap the `<Router AppAssembly="@typeof(App).Assembly">` component with:
```razor
@using Microsoft.AspNetCore.Components.Authorization

<CascadingAuthenticationState>
    ...
</CascadingAuthenticationState>
```
4. Surround the content in MainLayout.razor with
```razor
@using Microsoft.AspNetCore.Components.Authorization

@inherits LayoutComponentBase
<AuthorizeView>
    <Authorized>
        ...
    </Authorized>
    <NotAuthorized>
        <RedirectToWristbandLogin></RedirectToWristbandLogin>
    </NotAuthorized>
</AuthorizeView>
```
5. Add the following usings to Program.cs
```csharp
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Wristband;
```
6. Add the following services code to Program.cs
```csharp
var builder = WebAssemblyHostBuilder.CreateDefault(args);
...
var services = builder.Services;
...
services.AddHttpClient();
services.AddAuthorizationCore();
services.AddCascadingAuthenticationState();
services.AddSingleton<CustomAuthenticationLocalStorageService>();
services.AddSingleton<CustomAuthenticationStateProvider>();
services.AddSingleton<AuthenticationStateProvider>(
    s => s.GetRequiredService<CustomAuthenticationStateProvider>());
```