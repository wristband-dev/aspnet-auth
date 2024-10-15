using Apps.Blazor;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

var services = builder.Services;

services.AddHttpClient();
services.AddAuthorizationCore();
services.AddCascadingAuthenticationState();
services.AddSingleton<CustomAuthenticationLocalStorageService>();
services.AddSingleton<CustomAuthenticationStateProvider>();
services.AddSingleton<AuthenticationStateProvider>(
    s => s.GetRequiredService<CustomAuthenticationStateProvider>());

await builder.Build().RunAsync();
