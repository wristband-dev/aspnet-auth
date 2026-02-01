using System.Security.Claims;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandSessionResponseTests
{
    private HttpContext CreateContextWithClaims(params Claim[] claims)
    {
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(claims, "Bearer");
        context.User = new ClaimsPrincipal(identity);
        return context;
    }

    [Fact]
    public void GetSessionResponse_WithValidSession_ReturnsResponse()
    {
        var context = CreateContextWithClaims(
            new Claim("userId", "user123"),
            new Claim("tenantId", "tenant456")
        );

        var result = context.GetSessionResponse();

        Assert.Equal("user123", result.UserId);
        Assert.Equal("tenant456", result.TenantId);
        Assert.Null(result.Metadata);
    }

    [Fact]
    public void GetSessionResponse_WithMetadata_IncludesMetadata()
    {
        var context = CreateContextWithClaims(
            new Claim("userId", "user123"),
            new Claim("tenantId", "tenant456")
        );
        var metadata = new { email = "test@example.com", theme = "dark" };

        var result = context.GetSessionResponse(metadata);

        Assert.NotNull(result.Metadata);
    }

    [Fact]
    public void GetSessionResponse_SetsNoCacheHeaders()
    {
        var context = CreateContextWithClaims(
            new Claim("userId", "user123"),
            new Claim("tenantId", "tenant456")
        );

        context.GetSessionResponse();

        Assert.Equal("no-store", context.Response.Headers["Cache-Control"]);
        Assert.Equal("no-cache", context.Response.Headers["Pragma"]);
    }

    [Fact]
    public void GetSessionResponse_MissingUserId_ThrowsInvalidOperationException()
    {
        var context = CreateContextWithClaims(new Claim("tenantId", "tenant456"));

        var exception = Assert.Throws<InvalidOperationException>(() =>
            context.GetSessionResponse());

        Assert.Contains("missing required userId", exception.Message);
    }

    [Fact]
    public void GetSessionResponse_MissingTenantId_ThrowsInvalidOperationException()
    {
        var context = CreateContextWithClaims(new Claim("userId", "user123"));

        var exception = Assert.Throws<InvalidOperationException>(() =>
            context.GetSessionResponse());

        Assert.Contains("missing required tenantId", exception.Message);
    }

    [Fact]
    public void GetTokenResponse_WithValidSession_ReturnsResponse()
    {
        var context = CreateContextWithClaims(
            new Claim("accessToken", "token123"),
            new Claim("expiresAt", "123456789")
        );

        var result = context.GetTokenResponse();

        Assert.Equal("token123", result.AccessToken);
        Assert.Equal(123456789, result.ExpiresAt);
    }

    [Fact]
    public void GetTokenResponse_SetsNoCacheHeaders()
    {
        var context = CreateContextWithClaims(
            new Claim("accessToken", "token123"),
            new Claim("expiresAt", "123456789")
        );

        context.GetTokenResponse();

        Assert.Equal("no-store", context.Response.Headers["Cache-Control"]);
        Assert.Equal("no-cache", context.Response.Headers["Pragma"]);
    }

    [Fact]
    public void GetTokenResponse_MissingAccessToken_ThrowsInvalidOperationException()
    {
        var context = CreateContextWithClaims(new Claim("expiresAt", "123456789"));

        var exception = Assert.Throws<InvalidOperationException>(() =>
            context.GetTokenResponse());

        Assert.Contains("missing required accessToken", exception.Message);
    }

    [Fact]
    public void GetTokenResponse_MissingExpiresAt_ThrowsInvalidOperationException()
    {
        var context = CreateContextWithClaims(new Claim("accessToken", "token123"));

        var exception = Assert.Throws<InvalidOperationException>(() =>
            context.GetTokenResponse());

        Assert.Contains("missing required expiresAt", exception.Message);
    }

    [Fact]
    public void GetTokenResponse_NegativeExpiresAt_ThrowsInvalidOperationException()
    {
        var context = CreateContextWithClaims(
            new Claim("accessToken", "token123"),
            new Claim("expiresAt", "-1")
        );

        var exception = Assert.Throws<InvalidOperationException>(() =>
            context.GetTokenResponse());

        Assert.Contains("missing required expiresAt", exception.Message);
    }
}
