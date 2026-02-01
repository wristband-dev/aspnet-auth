using System.Security.Claims;
using System.Text.Json;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandSessionRetrievalTests
{
    private HttpContext CreateContextWithClaims(params Claim[] claims)
    {
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);
        return context;
    }

    [Fact]
    public void GetSessionClaim_ReturnsClaimValue()
    {
        var context = CreateContextWithClaims(new Claim("userId", "user123"));

        var result = context.GetSessionClaim("userId");

        Assert.Equal("user123", result);
    }

    [Fact]
    public void GetSessionClaim_NonExistentClaim_ReturnsNull()
    {
        var context = CreateContextWithClaims();

        var result = context.GetSessionClaim("nonExistent");

        Assert.Null(result);
    }

    [Fact]
    public void IsAuthenticated_WhenTrue_ReturnsTrue()
    {
        var context = CreateContextWithClaims(new Claim("isAuthenticated", "true"));

        var result = context.IsAuthenticated();

        Assert.True(result);
    }

    [Fact]
    public void IsAuthenticated_WhenFalse_ReturnsFalse()
    {
        var context = CreateContextWithClaims(new Claim("isAuthenticated", "false"));

        var result = context.IsAuthenticated();

        Assert.False(result);
    }

    [Fact]
    public void IsAuthenticated_WhenMissing_ReturnsFalse()
    {
        var context = CreateContextWithClaims();

        var result = context.IsAuthenticated();

        Assert.False(result);
    }

    [Fact]
    public void GetAccessToken_ReturnsToken()
    {
        var context = CreateContextWithClaims(new Claim("accessToken", "token123"));

        var result = context.GetAccessToken();

        Assert.Equal("token123", result);
    }

    [Fact]
    public void GetRefreshToken_ReturnsToken()
    {
        var context = CreateContextWithClaims(new Claim("refreshToken", "refresh123"));

        var result = context.GetRefreshToken();

        Assert.Equal("refresh123", result);
    }

    [Fact]
    public void GetExpiresAt_ReturnsTimestamp()
    {
        var context = CreateContextWithClaims(new Claim("expiresAt", "123456789"));

        var result = context.GetExpiresAt();

        Assert.Equal(123456789, result);
    }

    [Fact]
    public void GetExpiresAt_InvalidValue_ReturnsNull()
    {
        var context = CreateContextWithClaims(new Claim("expiresAt", "invalid"));

        var result = context.GetExpiresAt();

        Assert.Null(result);
    }

    [Fact]
    public void GetUserId_ReturnsUserId()
    {
        var context = CreateContextWithClaims(new Claim("userId", "user123"));

        var result = context.GetUserId();

        Assert.Equal("user123", result);
    }

    [Fact]
    public void GetTenantId_ReturnsTenantId()
    {
        var context = CreateContextWithClaims(new Claim("tenantId", "tenant456"));

        var result = context.GetTenantId();

        Assert.Equal("tenant456", result);
    }

    [Fact]
    public void GetTenantName_ReturnsTenantName()
    {
        var context = CreateContextWithClaims(new Claim("tenantName", "acme"));

        var result = context.GetTenantName();

        Assert.Equal("acme", result);
    }

    [Fact]
    public void GetIdentityProviderName_ReturnsProviderName()
    {
        var context = CreateContextWithClaims(new Claim("identityProviderName", "Wristband"));

        var result = context.GetIdentityProviderName();

        Assert.Equal("Wristband", result);
    }

    [Fact]
    public void GetTenantCustomDomain_ReturnsDomain()
    {
        var context = CreateContextWithClaims(new Claim("tenantCustomDomain", "custom.domain.com"));

        var result = context.GetTenantCustomDomain();

        Assert.Equal("custom.domain.com", result);
    }

    [Fact]
    public void GetRoles_WithValidJson_ReturnsRoles()
    {
        var roles = new List<UserInfoRole>
        {
            new UserInfoRole { Id = "role1", Name = "Admin", DisplayName = "Administrator" },
            new UserInfoRole { Id = "role2", Name = "User", DisplayName = "Standard User" }
        };
        var rolesJson = JsonSerializer.Serialize(roles);
        var context = CreateContextWithClaims(new Claim("roles", rolesJson));

        var result = context.GetRoles();

        Assert.Equal(2, result.Count);
        Assert.Equal("Admin", result[0].Name);
        Assert.Equal("User", result[1].Name);
    }

    [Fact]
    public void GetRoles_WithMissingClaim_ReturnsEmptyList()
    {
        var context = CreateContextWithClaims();

        var result = context.GetRoles();

        Assert.Empty(result);
    }

    [Fact]
    public void GetRoles_WithInvalidJson_ReturnsEmptyList()
    {
        var context = CreateContextWithClaims(new Claim("roles", "invalid json"));

        var result = context.GetRoles();

        Assert.Empty(result);
    }
}
