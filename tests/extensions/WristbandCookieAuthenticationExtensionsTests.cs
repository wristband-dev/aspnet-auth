using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandCookieAuthenticationExtensionsTests
{
    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToLogin_Returns401()
    {
        // Arrange
        var options = new CookieAuthenticationOptions();
        options.UseWristbandApiStatusCodes();

        var context = new RedirectContext<CookieAuthenticationOptions>(
            new DefaultHttpContext(),
            new AuthenticationScheme("Cookies", "Cookies", typeof(CookieAuthenticationHandler)),
            options,
            new AuthenticationProperties(),
            "/"
        );

        // Act
        await options.Events.OnRedirectToLogin(context);

        // Assert
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToAccessDenied_Returns403()
    {
        // Arrange
        var options = new CookieAuthenticationOptions();
        options.UseWristbandApiStatusCodes();

        var context = new RedirectContext<CookieAuthenticationOptions>(
            new DefaultHttpContext(),
            new AuthenticationScheme("Cookies", "Cookies", typeof(CookieAuthenticationHandler)),
            options,
            new AuthenticationProperties(),
            "/"
        );

        // Act
        await options.Events.OnRedirectToAccessDenied(context);

        // Assert
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
    }

    [Fact]
    public void UseWristbandApiStatusCodes_ReturnsOptions_ForChaining()
    {
        // Arrange
        var options = new CookieAuthenticationOptions();

        // Act
        var result = options.UseWristbandApiStatusCodes();

        // Assert
        Assert.Same(options, result);
    }

    [Fact]
    public void UseWristbandApiStatusCodes_WithNullOptions_ThrowsArgumentNullException()
    {
        // Arrange
        CookieAuthenticationOptions options = null!;

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(
            () => options.UseWristbandApiStatusCodes());
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToLogin_DoesNotModifyOtherResponseProperties()
    {
        // Arrange
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

        // Act
        await options.Events.OnRedirectToLogin(context);

        // Assert
        Assert.Equal("TestValue", context.Response.Headers["X-Test"]);
    }

    [Fact]
    public async Task UseWristbandApiStatusCodes_OnRedirectToAccessDenied_DoesNotModifyOtherResponseProperties()
    {
        // Arrange
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

        // Act
        await options.Events.OnRedirectToAccessDenied(context);

        // Assert
        Assert.Equal("TestValue", context.Response.Headers["X-Test"]);
    }
}
