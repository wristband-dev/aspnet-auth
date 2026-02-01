using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandSessionConfigurationTests
{
    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToLogin_Returns401()
    {
        var options = new CookieAuthenticationOptions();
        options.UseWristbandApiStatusCodes();
        var context = new RedirectContext<CookieAuthenticationOptions>(
            new DefaultHttpContext(),
            new AuthenticationScheme("Cookies", "Cookies", typeof(CookieAuthenticationHandler)),
            options,
            new AuthenticationProperties(),
            "/"
        );

        await options.Events.OnRedirectToLogin(context);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToAccessDenied_Returns403()
    {
        var options = new CookieAuthenticationOptions();
        options.UseWristbandApiStatusCodes();
        var context = new RedirectContext<CookieAuthenticationOptions>(
            new DefaultHttpContext(),
            new AuthenticationScheme("Cookies", "Cookies", typeof(CookieAuthenticationHandler)),
            options,
            new AuthenticationProperties(),
            "/"
        );

        await options.Events.OnRedirectToAccessDenied(context);

        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public void UseWristbandApiStatusCodes_ReturnsOptions_ForChaining()
    {
        var options = new CookieAuthenticationOptions();

        var result = options.UseWristbandApiStatusCodes();

        Assert.Same(options, result);
    }

    [Fact]
    public void UseWristbandApiStatusCodes_WithNullOptions_ThrowsArgumentNullException()
    {
        CookieAuthenticationOptions options = null!;

        var exception = Assert.Throws<ArgumentNullException>(() => options.UseWristbandApiStatusCodes());

        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToLogin_DoesNotModifyOtherResponseProperties()
    {
        var options = new CookieAuthenticationOptions();
        options.UseWristbandApiStatusCodes();
        var httpContext = new DefaultHttpContext();
        httpContext.Response.Headers["X-Test"] = "TestValue";
        var context = new RedirectContext<CookieAuthenticationOptions>(
            httpContext,
            new AuthenticationScheme("Cookies", "Cookies", typeof(CookieAuthenticationHandler)),
            options,
            new AuthenticationProperties(),
            "/"
        );

        await options.Events.OnRedirectToLogin(context);

        Assert.Equal("TestValue", context.Response.Headers["X-Test"]);
    }

    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToAccessDenied_DoesNotModifyOtherResponseProperties()
    {
        var options = new CookieAuthenticationOptions();
        options.UseWristbandApiStatusCodes();
        var httpContext = new DefaultHttpContext();
        httpContext.Response.Headers["X-Test"] = "TestValue";
        var context = new RedirectContext<CookieAuthenticationOptions>(
            httpContext,
            new AuthenticationScheme("Cookies", "Cookies", typeof(CookieAuthenticationHandler)),
            options,
            new AuthenticationProperties(),
            "/"
        );

        await options.Events.OnRedirectToAccessDenied(context);

        Assert.Equal("TestValue", context.Response.Headers["X-Test"]);
    }

    [Fact]
    public void UseWristbandSessionConfig_SetsCorrectDefaults()
    {
        var options = new CookieAuthenticationOptions();

        options.UseWristbandSessionConfig();

        Assert.Equal("session", options.Cookie.Name);
        Assert.True(options.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, options.Cookie.SecurePolicy);
        Assert.Equal(SameSiteMode.Lax, options.Cookie.SameSite);
        Assert.Equal("/", options.Cookie.Path);
        Assert.True(options.SlidingExpiration);
        Assert.Equal(TimeSpan.FromHours(1), options.ExpireTimeSpan);
    }

    [Fact]
    public void UseWristbandSessionConfig_ConfiguresApiStatusCodes()
    {
        var options = new CookieAuthenticationOptions();

        options.UseWristbandSessionConfig();

        Assert.NotNull(options.Events.OnRedirectToLogin);
        Assert.NotNull(options.Events.OnRedirectToAccessDenied);
    }

    [Fact]
    public void UseWristbandSessionConfig_ReturnsOptions_ForChaining()
    {
        var options = new CookieAuthenticationOptions();

        var result = options.UseWristbandSessionConfig();

        Assert.Same(options, result);
    }

    [Fact]
    public void UseWristbandSessionMiddleware_ReturnsApplicationBuilder()
    {
        var mockAppBuilder = new Mock<IApplicationBuilder>();
        mockAppBuilder.Setup(x => x.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()))
            .Returns(mockAppBuilder.Object);

        var result = mockAppBuilder.Object.UseWristbandSessionMiddleware();

        Assert.NotNull(result);
    }

    [Fact]
    public void UseWristbandApiStatusCodes_WithNullEvents_CreatesNewEvents()
    {
        var options = new CookieAuthenticationOptions
        {
            Events = null!
        };

        options.UseWristbandApiStatusCodes();

        Assert.NotNull(options.Events);
        Assert.NotNull(options.Events.OnRedirectToLogin);
        Assert.NotNull(options.Events.OnRedirectToAccessDenied);
    }
}
