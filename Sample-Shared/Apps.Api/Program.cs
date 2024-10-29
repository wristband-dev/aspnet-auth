using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Wristband;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

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

services.AddDistributedMemoryCache();
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
    return new WristbandAuthService(httpClientFactory, authConfig, loginConfig, logoutConfig, null);
});

services.AddEndpointsApiExplorer();
services.AddSwaggerGen();
services.ConfigureHttpJsonOptions(json =>
{
    json.SerializerOptions.WriteIndented = true;
});

var app = builder.Build();

if (!builder.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

app.UseHsts();
app.UseSwagger();
app.UseSwaggerUI();
app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseSession();
app.UseMiddleware<WristbandAuthMiddleware>();
app.MapDefaultEndpoints();
app.MapWristbandEndpoints();

app.MapGet("/", () => "Please visit /api/swagger for API documentation")
    .ExcludeFromDescription();
app.MapGet("/unprotected", () => Results.Ok(new { Message = "This is an unprotected route.", Value = 1 }));

app.MapGet("/protected",
        [Authorize(/*"some:permission"*/)]
        () => Results.Ok(new { Message = "This is a protected route.", Value = 1 }));

app.Run();
