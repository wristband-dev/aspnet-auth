using System.Security.Claims;

using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandSessionManagementTests
{
    [Fact]
    public void CreateSession_CreatesPrincipalWithClaims()
    {
        var context = new DefaultHttpContext();
        var claims = new[]
        {
            new Claim("userId", "user123"),
            new Claim("tenantId", "tenant456")
        };

        context.CreateSession(claims);

        Assert.NotNull(context.User);
        Assert.True(context.User.Identity?.IsAuthenticated);
        Assert.Equal("user123", context.User.FindFirst("userId")?.Value);
        Assert.Equal("tenant456", context.User.FindFirst("tenantId")?.Value);
    }

    [Fact]
    public void CreateSession_SetsSaveFlag()
    {
        var context = new DefaultHttpContext();
        var claims = new[] { new Claim("userId", "user123") };

        context.CreateSession(claims);

        Assert.True(context.Items.ContainsKey("WristbandSessionNeedsSave"));
        Assert.True((bool)context.Items["WristbandSessionNeedsSave"]!);
    }

    [Fact]
    public void CreateSessionFromCallback_WithValidData_CreatesSession()
    {
        var context = new DefaultHttpContext();
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant456",
            ApplicationId = "app789",
            IdentityProviderName = "Wristband",
            Email = "test@example.com"
        };
        var callbackData = new CallbackData(
            "access-token",
            123456789,
            3600,
            "id-token",
            "refresh-token",
            userInfo,
            "tenant-name",
            null,
            null,
            null
        );

        context.CreateSessionFromCallback(callbackData);

        Assert.True(context.User.Identity?.IsAuthenticated);
        Assert.Equal("user123", context.GetUserId());
        Assert.Equal("tenant456", context.GetTenantId());
        Assert.Equal("access-token", context.GetAccessToken());
        Assert.Equal("refresh-token", context.GetRefreshToken());
    }

    [Fact]
    public void CreateSessionFromCallback_WithCustomClaims_IncludesCustomClaims()
    {
        var context = new DefaultHttpContext();
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant456",
            ApplicationId = "app789",
            IdentityProviderName = "Wristband",
            Email = "test@example.com"
        };
        var callbackData = new CallbackData(
            "access-token",
            123456789,
            3600,
            "id-token",
            null,
            userInfo,
            "tenant-name",
            null,
            null,
            null
        );
        var customClaims = new[]
        {
            new Claim("role", "admin"),
            new Claim("theme", "dark")
        };

        context.CreateSessionFromCallback(callbackData, customClaims);

        Assert.Equal("admin", context.GetSessionClaim("role"));
        Assert.Equal("dark", context.GetSessionClaim("theme"));
    }

    [Fact]
    public void CreateSessionFromCallback_WithNullCallbackData_ThrowsArgumentNullException()
    {
        var context = new DefaultHttpContext();

        var exception = Assert.Throws<ArgumentNullException>(() =>
            context.CreateSessionFromCallback(null!));

        Assert.Equal("callbackData", exception.ParamName);
    }

    [Fact]
    public void CreateSessionFromCallback_WithoutRefreshToken_DoesNotIncludeRefreshTokenClaim()
    {
        var context = new DefaultHttpContext();
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant456",
            ApplicationId = "app789",
            IdentityProviderName = "Wristband",
            Email = "test@example.com"
        };
        var callbackData = new CallbackData(
            "access-token",
            123456789,
            3600,
            "id-token",
            null,
            userInfo,
            "tenant-name",
            null,
            null,
            null
        );

        context.CreateSessionFromCallback(callbackData);

        Assert.Null(context.GetRefreshToken());
    }

    [Fact]
    public void CreateSessionFromCallback_WithTenantCustomDomain_IncludesTenantCustomDomainClaim()
    {
        var context = new DefaultHttpContext();
        var userInfo = new UserInfo
        {
            UserId = "user123",
            TenantId = "tenant456",
            ApplicationId = "app789",
            IdentityProviderName = "Wristband",
            Email = "test@example.com"
        };
        var callbackData = new CallbackData(
            "access-token",
            123456789,
            3600,
            "id-token",
            null,
            userInfo,
            "tenant-name",
            "custom.domain.com",
            null,
            null
        );

        context.CreateSessionFromCallback(callbackData);

        Assert.Equal("custom.domain.com", context.GetTenantCustomDomain());
    }

    [Fact]
    public void DestroySession_SetsDeleteFlag()
    {
        var context = new DefaultHttpContext();

        context.DestroySession();

        Assert.True(context.Items.ContainsKey("WristbandSessionNeedsDelete"));
        Assert.True((bool)context.Items["WristbandSessionNeedsDelete"]!);
    }
}
