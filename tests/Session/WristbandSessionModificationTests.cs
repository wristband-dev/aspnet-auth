using System.Security.Claims;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandSessionModificationTests
{
    private HttpContext CreateAuthenticatedContext()
    {
        var context = new DefaultHttpContext();
        var claims = new[] { new Claim("userId", "user123") };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);
        return context;
    }

    [Fact]
    public void SetSessionClaim_AddsNewClaim()
    {
        var context = CreateAuthenticatedContext();

        context.SetSessionClaim("theme", "dark");

        Assert.Equal("dark", context.GetSessionClaim("theme"));
    }

    [Fact]
    public void SetSessionClaim_UpdatesExistingClaim()
    {
        var context = CreateAuthenticatedContext();
        context.SetSessionClaim("theme", "light");

        context.SetSessionClaim("theme", "dark");

        Assert.Equal("dark", context.GetSessionClaim("theme"));
    }

    [Fact]
    public void SetSessionClaim_SetsSaveFlag()
    {
        var context = CreateAuthenticatedContext();

        context.SetSessionClaim("theme", "dark");

        Assert.True(context.Items.ContainsKey("WristbandSessionNeedsSave"));
        Assert.True((bool)context.Items["WristbandSessionNeedsSave"]!);
    }

    [Fact]
    public void SetSessionClaim_WhenNotAuthenticated_ThrowsInvalidOperationException()
    {
        var context = new DefaultHttpContext();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            context.SetSessionClaim("theme", "dark"));

        Assert.Contains("Cannot set session claim", exception.Message);
    }

    [Fact]
    public void RemoveSessionClaim_RemovesExistingClaim()
    {
        var context = CreateAuthenticatedContext();
        context.SetSessionClaim("theme", "dark");

        context.RemoveSessionClaim("theme");

        Assert.Null(context.GetSessionClaim("theme"));
    }

    [Fact]
    public void RemoveSessionClaim_SetsSaveFlag()
    {
        var context = CreateAuthenticatedContext();
        context.SetSessionClaim("theme", "dark");
        context.Items.Clear();

        context.RemoveSessionClaim("theme");

        Assert.True(context.Items.ContainsKey("WristbandSessionNeedsSave"));
        Assert.True((bool)context.Items["WristbandSessionNeedsSave"]!);
    }

    [Fact]
    public void RemoveSessionClaim_WhenNotAuthenticated_ThrowsInvalidOperationException()
    {
        var context = new DefaultHttpContext();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            context.RemoveSessionClaim("theme"));

        Assert.Contains("Cannot update session claim", exception.Message);
    }

    [Fact]
    public void RemoveSessionClaim_NonExistentClaim_DoesNotThrow()
    {
        var context = CreateAuthenticatedContext();

        context.RemoveSessionClaim("nonExistent");

        Assert.Null(context.GetSessionClaim("nonExistent"));
    }
}
