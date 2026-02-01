using System.Security.Claims;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandContextExtensionsTests
{
    [Fact]
    public void GetJwt_ReturnsNull_WhenAuthorizationHeaderMissing()
    {
        var context = new DefaultHttpContext();
        var result = context.GetJwt();
        Assert.Null(result);
    }

    [Fact]
    public void GetJwt_ReturnsToken_WhenBearerTokenPresent()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Bearer test-token-123";

        var result = context.GetJwt();
        Assert.Equal("test-token-123", result);
    }

    [Fact]
    public void GetJwt_ReturnsNull_WhenAuthorizationHeaderIsNotBearer()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Basic credentials";

        var result = context.GetJwt();
        Assert.Null(result);
    }

    [Fact]
    public void GetJwt_ReturnsNull_WhenBearerTokenIsEmpty()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Bearer ";

        var result = context.GetJwt();
        Assert.Null(result);
    }

    [Fact]
    public void GetJwtPayload_ReturnsPayloadWithClaims_WhenUserAuthenticated()
    {
        var context = new DefaultHttpContext();
        var claims = new[]
        {
            new Claim("sub", "user-123"),
            new Claim("iss", "https://test.wristband.dev"),
            new Claim("exp", "1735689600"),
            new Claim("tnt_id", "tenant-456")
        };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        var payload = context.GetJwtPayload();
        Assert.Equal("user-123", payload.Sub);
        Assert.Equal("https://test.wristband.dev", payload.Iss);
        Assert.Equal(1735689600, payload.Exp);
        Assert.NotNull(payload.Claims);
        Assert.Equal("tenant-456", payload.Claims["tnt_id"]);
    }

    [Fact]
    public void GetJwtPayload_ReturnsPayloadWithNullValues_WhenUserNotAuthenticated()
    {
        var context = new DefaultHttpContext();
        context.User = new ClaimsPrincipal(new ClaimsIdentity());

        var payload = context.GetJwtPayload();
        Assert.Null(payload.Sub);
        Assert.Null(payload.Iss);
        Assert.Null(payload.Exp);
    }

    [Fact]
    public void GetJwtPayload_HandlesMultipleAudiences()
    {
        var context = new DefaultHttpContext();
        var claims = new[]
        {
            new Claim("sub", "user-123"),
            new Claim("aud", "audience-1"),
            new Claim("aud", "audience-2")
        };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        var payload = context.GetJwtPayload();
        Assert.NotNull(payload.Aud);
        Assert.Equal(2, payload.Aud.Length);
        Assert.Contains("audience-1", payload.Aud);
        Assert.Contains("audience-2", payload.Aud);
    }

    [Fact]
    public void GetJwtPayload_ReturnsAllStandardClaims()
    {
        var context = new DefaultHttpContext();
        var claims = new[]
        {
            new Claim("iss", "https://issuer.com"),
            new Claim("sub", "user-123"),
            new Claim("aud", "audience-1"),
            new Claim("exp", "1735689600"),
            new Claim("iat", "1735686000"),
            new Claim("nbf", "1735686000"),
            new Claim("jti", "jwt-id-123")
        };
        context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        var payload = context.GetJwtPayload();
        Assert.Equal("https://issuer.com", payload.Iss);
        Assert.Equal("user-123", payload.Sub);
        Assert.NotNull(payload.Aud);
        Assert.Single(payload.Aud);
        Assert.Equal("audience-1", payload.Aud[0]);
        Assert.Equal(1735689600, payload.Exp);
        Assert.Equal(1735686000, payload.Iat);
        Assert.Equal(1735686000, payload.Nbf);
        Assert.Equal("jwt-id-123", payload.Jti);
    }
}
