using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandEndpointExtensionsTests
{
    [Fact]
    public void RequireWristbandSession_ForEndpoint_ReturnsBuilder()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var endpoint = app.MapGet("/test", () => "OK");
        var result = endpoint.RequireWristbandSession();

        Assert.Same(endpoint, result);
    }

    [Fact]
    public void RequireWristbandSession_ForRouteGroup_ReturnsBuilder()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var group = app.MapGroup("/api");
        var result = group.RequireWristbandSession();

        Assert.Same(group, result);
    }

    [Fact]
    public void RequireWristbandJwt_ForEndpoint_ReturnsBuilder()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var endpoint = app.MapGet("/test", () => "OK");
        var result = endpoint.RequireWristbandJwt();

        Assert.Same(endpoint, result);
    }

    [Fact]
    public void RequireWristbandJwt_ForRouteGroup_ReturnsBuilder()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var group = app.MapGroup("/api");
        var result = group.RequireWristbandJwt();

        Assert.Same(group, result);
    }

    [Fact]
    public void RequireWristbandMultiAuth_ForEndpoint_ReturnsBuilder()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var endpoint = app.MapGet("/test", () => "OK");
        var result = endpoint.RequireWristbandMultiAuth();

        Assert.Same(endpoint, result);
    }

    [Fact]
    public void RequireWristbandMultiAuth_ForRouteGroup_ReturnsBuilder()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var group = app.MapGroup("/api");
        var result = group.RequireWristbandMultiAuth();

        Assert.Same(group, result);
    }

    [Fact]
    public void RequireWristbandSession_ForEndpoint_CanBeChained()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var result = app.MapGet("/test", () => "OK")
            .RequireWristbandSession()
            .WithName("TestEndpoint");

        Assert.NotNull(result);
    }

    [Fact]
    public void RequireWristbandJwt_ForEndpoint_CanBeChained()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var result = app.MapGet("/test", () => "OK")
            .RequireWristbandJwt()
            .WithName("TestEndpoint");

        Assert.NotNull(result);
    }

    [Fact]
    public void RequireWristbandMultiAuth_ForEndpoint_CanBeChained()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var result = app.MapGet("/test", () => "OK")
            .RequireWristbandMultiAuth()
            .WithName("TestEndpoint");

        Assert.NotNull(result);
    }

    [Fact]
    public void RequireWristbandSession_ForRouteGroup_CanBeChained()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var result = app.MapGroup("/api")
            .RequireWristbandSession();

        var endpoint = result.MapGet("/test", () => "OK");
        Assert.NotNull(endpoint);
    }

    [Fact]
    public void RequireWristbandJwt_ForRouteGroup_CanBeChained()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var result = app.MapGroup("/api")
            .RequireWristbandJwt();

        var endpoint = result.MapGet("/test", () => "OK");
        Assert.NotNull(endpoint);
    }

    [Fact]
    public void RequireWristbandMultiAuth_ForRouteGroup_CanBeChained()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddAuthorization();
        var app = builder.Build();

        var result = app.MapGroup("/api")
            .RequireWristbandMultiAuth();

        var endpoint = result.MapGet("/test", () => "OK");
        Assert.NotNull(endpoint);
    }
}
