using System.Reflection;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandAuthHandlerTests
{
    private readonly Mock<IWristbandAuthService> _mockAuthService;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly WristbandCsrfOptions _csrfOptions;
    private readonly WristbandAuthHandler _handler;

    public WristbandAuthHandlerTests()
    {
        _mockAuthService = new Mock<IWristbandAuthService>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        _csrfOptions = new WristbandCsrfOptions();

        _handler = new WristbandAuthHandler(
            _mockAuthService.Object,
            _mockHttpContextAccessor.Object,
            Options.Create(_csrfOptions));
    }

    [Fact]
    public void Constructor_InitializesHandler()
    {
        Assert.NotNull(_handler);
    }

    [Fact]
    public async Task HandleRequirementAsync_FailsWhenHttpContextIsNull()
    {
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns((HttpContext?)null);

        var requirement = new WristbandAuthRequirement(AuthStrategy.Session);
        var authContext = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(),
            null);

        await _handler.HandleAsync(authContext);

        Assert.False(authContext.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_SucceedsWithSessionStrategy()
    {
        var claims = new[] { new Claim("userId", "test-user") };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);
        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ReturnsAsync((TokenData?)null);

        var requirement = new WristbandAuthRequirement(AuthStrategy.Session);
        var authContext = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(),
            null);

        await _handler.HandleAsync(authContext);

        Assert.True(authContext.HasSucceeded);
        Assert.False(authContext.HasFailed);
    }

    [Fact]
    public async Task HandleRequirementAsync_SucceedsWithJwtStrategy()
    {
        var claims = new[] { new Claim("sub", "jwt-user") };
        var httpContext = CreateAuthenticatedHttpContext(JwtBearerDefaults.AuthenticationScheme, true, claims);

        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var requirement = new WristbandAuthRequirement(AuthStrategy.Jwt);
        var authContext = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(),
            null);

        await _handler.HandleAsync(authContext);

        Assert.True(authContext.HasSucceeded);
        Assert.False(authContext.HasFailed);
    }

    [Fact]
    public async Task HandleRequirementAsync_TriesSessionThenJwt_SucceedsOnSecond()
    {
        var claims = new[] { new Claim("sub", "jwt-user") };
        var httpContext = CreateAuthenticatedHttpContext(JwtBearerDefaults.AuthenticationScheme, true, claims);

        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var requirement = new WristbandAuthRequirement(AuthStrategy.Session, AuthStrategy.Jwt);
        var authContext = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(),
            null);

        await _handler.HandleAsync(authContext);

        Assert.True(authContext.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_TriesJwtThenSession_SucceedsOnFirst()
    {
        var claims = new[] { new Claim("sub", "jwt-user") };
        var httpContext = CreateAuthenticatedHttpContext(JwtBearerDefaults.AuthenticationScheme, true, claims);

        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var requirement = new WristbandAuthRequirement(AuthStrategy.Jwt, AuthStrategy.Session);
        var authContext = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(),
            null);

        await _handler.HandleAsync(authContext);

        Assert.True(authContext.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_FailsWhenAllStrategiesFail()
    {
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, false);

        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        var requirement = new WristbandAuthRequirement(AuthStrategy.Session, AuthStrategy.Jwt);
        var authContext = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(),
            null);

        await _handler.HandleAsync(authContext);

        Assert.False(authContext.HasSucceeded);
        Assert.True(authContext.HasFailed);
    }

    [Fact]
    public async Task HandleRequirementAsync_StopsOnFirstSuccess()
    {
        var sessionClaims = new[] { new Claim("userId", "test-user") };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, sessionClaims);

        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);
        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ReturnsAsync((TokenData?)null);

        var requirement = new WristbandAuthRequirement(AuthStrategy.Session, AuthStrategy.Jwt);
        var authContext = new AuthorizationHandlerContext(
            new[] { requirement },
            new ClaimsPrincipal(),
            null);

        await _handler.HandleAsync(authContext);

        Assert.True(authContext.HasSucceeded);
    }

    [Fact]
    public async Task TrySessionAuth_FailsWhenNotAuthenticated()
    {
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, false);
        var result = await InvokeTrySessionAuth(httpContext);
        Assert.False(result);
    }

    [Fact]
    public async Task TrySessionAuth_SucceedsWhenAuthenticated()
    {
        var claims = new[] { new Claim("userId", "test-user") };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);
        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ReturnsAsync((TokenData?)null);

        var result = await InvokeTrySessionAuth(httpContext);
        Assert.True(result);
    }

    [Fact]
    public async Task TrySessionAuth_SetsSessionSaveFlag()
    {
        var claims = new[] { new Claim("userId", "test-user") };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ReturnsAsync((TokenData?)null);

        await InvokeTrySessionAuth(httpContext);
        Assert.True(httpContext.Items.ContainsKey("WristbandSessionNeedsSave"));
        Assert.True((bool)httpContext.Items["WristbandSessionNeedsSave"]!);
    }

    [Fact]
    public async Task TrySessionAuth_ValidatesCsrfTokenWhenEnabled()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfHeaderName = "X-CSRF-TOKEN"
        };

        var handler = new WristbandAuthHandler(
            _mockAuthService.Object,
            _mockHttpContextAccessor.Object,
            Options.Create(csrfOptions));

        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("csrf_token", "valid-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);
        httpContext.Request.Headers["X-CSRF-TOKEN"] = "valid-token";

        var result = await InvokeTrySessionAuth(httpContext, handler);

        Assert.True(result);
    }

    [Fact]
    public async Task TrySessionAuth_FailsWhenCsrfTokenMismatch()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfHeaderName = "X-CSRF-TOKEN"
        };

        var handler = new WristbandAuthHandler(
            _mockAuthService.Object,
            _mockHttpContextAccessor.Object,
            Options.Create(csrfOptions));

        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("csrf_token", "session-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);
        httpContext.Request.Headers["X-CSRF-TOKEN"] = "different-token";

        var result = await InvokeTrySessionAuth(httpContext, handler);

        Assert.False(result);
    }

    [Fact]
    public async Task TrySessionAuth_FailsWhenCsrfTokenMissing()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfHeaderName = "X-CSRF-TOKEN"
        };

        var handler = new WristbandAuthHandler(
            _mockAuthService.Object,
            _mockHttpContextAccessor.Object,
            Options.Create(csrfOptions));

        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("csrf_token", "session-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        var result = await InvokeTrySessionAuth(httpContext, handler);

        Assert.False(result);
    }

    [Fact]
    public async Task TryJwtAuth_SucceedsWithValidJwt()
    {
        var claims = new[] { new Claim("sub", "jwt-user") };
        var httpContext = CreateAuthenticatedHttpContext(JwtBearerDefaults.AuthenticationScheme, true, claims);

        var result = await InvokeTryJwtAuth(httpContext);

        Assert.True(result);
    }

    [Fact]
    public async Task TryJwtAuth_FailsWithoutAuthentication()
    {
        var httpContext = CreateAuthenticatedHttpContext(JwtBearerDefaults.AuthenticationScheme, false);

        var result = await InvokeTryJwtAuth(httpContext);

        Assert.False(result);
    }

    private HttpContext CreateAuthenticatedHttpContext(string scheme, bool isAuthenticated, Claim[]? claims = null)
    {
        var httpContext = new DefaultHttpContext();

        var identity = isAuthenticated
            ? new ClaimsIdentity(claims ?? Array.Empty<Claim>(), scheme)
            : new ClaimsIdentity();

        var principal = new ClaimsPrincipal(identity);

        var authResult = isAuthenticated
            ? AuthenticateResult.Success(new AuthenticationTicket(principal, scheme))
            : AuthenticateResult.Fail("Not authenticated");

        var mockAuthService = new Mock<IAuthenticationService>();
        mockAuthService
            .Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), It.IsAny<string>()))
            .ReturnsAsync(authResult);

        var services = new ServiceCollection();
        services.AddSingleton(mockAuthService.Object);

        httpContext.RequestServices = services.BuildServiceProvider();
        httpContext.User = principal;

        return httpContext;
    }

    private async Task<bool> InvokeTrySessionAuth(HttpContext httpContext, WristbandAuthHandler? handler = null)
    {
        handler ??= _handler;
        var method = typeof(WristbandAuthHandler).GetMethod("TrySessionAuth", BindingFlags.NonPublic | BindingFlags.Instance);
        var task = (Task<bool>)method!.Invoke(handler, new object[] { httpContext })!;
        return await task;
    }

    private async Task<bool> InvokeTryJwtAuth(HttpContext httpContext, WristbandAuthHandler? handler = null)
    {
        handler ??= _handler;
        var method = typeof(WristbandAuthHandler).GetMethod("TryJwtAuth", BindingFlags.NonPublic | BindingFlags.Instance);
        var task = (Task<bool>)method!.Invoke(handler, new object[] { httpContext })!;
        return await task;
    }

    [Fact]
    public async Task TrySessionAuth_RefreshesExpiredToken()
    {
        var refreshToken = "refresh-token-123";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeMilliseconds();

        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("refreshToken", refreshToken),
            new Claim("expiresAt", expiresAt.ToString()),
            new Claim("accessToken", "old-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        var newTokenData = new TokenData(
            "new-access-token",
            DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds(),
            3600,
            "new-id-token",
            "new-refresh-token");

        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(refreshToken, expiresAt))
            .ReturnsAsync(newTokenData);

        var result = await InvokeTrySessionAuth(httpContext);

        Assert.True(result);
        _mockAuthService.Verify(x => x.RefreshTokenIfExpired(refreshToken, expiresAt), Times.Once);
    }

    [Fact]
    public async Task TrySessionAuth_UpdatesClaimsAfterTokenRefresh()
    {
        var refreshToken = "refresh-token-123";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeMilliseconds();

        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("refreshToken", refreshToken),
            new Claim("expiresAt", expiresAt.ToString()),
            new Claim("accessToken", "old-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        var newTokenData = new TokenData(
            "new-access-token",
            99999999999,
            3600,
            "new-id-token",
            "new-refresh-token");

        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(refreshToken, expiresAt))
            .ReturnsAsync(newTokenData);

        await InvokeTrySessionAuth(httpContext);

        var accessTokenClaim = httpContext.User.FindFirst("accessToken")?.Value;
        var refreshTokenClaim = httpContext.User.FindFirst("refreshToken")?.Value;
        var expiresAtClaim = httpContext.User.FindFirst("expiresAt")?.Value;

        Assert.Equal("new-access-token", accessTokenClaim);
        Assert.Equal("new-refresh-token", refreshTokenClaim);
        Assert.Equal("99999999999", expiresAtClaim);
    }

    [Fact]
    public async Task TrySessionAuth_FailsWhenTokenRefreshThrowsException()
    {
        var refreshToken = "refresh-token-123";
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeMilliseconds();

        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("refreshToken", refreshToken),
            new Claim("expiresAt", expiresAt.ToString())
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(refreshToken, expiresAt))
            .ThrowsAsync(new Exception("Token refresh failed"));

        var result = await InvokeTrySessionAuth(httpContext);

        Assert.False(result);
    }

    [Fact]
    public async Task TrySessionAuth_SkipsRefreshWhenNoRefreshToken()
    {
        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("expiresAt", "123456789")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        var result = await InvokeTrySessionAuth(httpContext);

        Assert.True(result);
        _mockAuthService.Verify(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()), Times.Never);
    }

    [Fact]
    public async Task TrySessionAuth_SkipsRefreshWhenNoExpiresAt()
    {
        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("refreshToken", "refresh-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        var result = await InvokeTrySessionAuth(httpContext);

        Assert.True(result);
        _mockAuthService.Verify(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()), Times.Never);
    }

    [Fact]
    public async Task TrySessionAuth_DoesNotUpdateClaimsWhenTokenNotRefreshed()
    {
        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("refreshToken", "refresh-token"),
            new Claim("expiresAt", "999999999999"),
            new Claim("accessToken", "current-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);

        _mockAuthService.Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ReturnsAsync((TokenData?)null);

        await InvokeTrySessionAuth(httpContext);

        var accessTokenClaim = httpContext.User.FindFirst("accessToken")?.Value;
        Assert.Equal("current-token", accessTokenClaim);
    }

    [Fact]
    public async Task TrySessionAuth_SucceedsWhenCsrfDisabled()
    {
        var claims = new[]
        {
            new Claim("userId", "test-user"),
            new Claim("csrf_token", "some-token")
        };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);
        // No CSRF header set

        var result = await InvokeTrySessionAuth(httpContext);

        Assert.True(result);
    }

    [Fact]
    public async Task TrySessionAuth_FailsWhenCsrfEnabledButNoSessionToken()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfHeaderName = "X-CSRF-TOKEN"
        };

        var handler = new WristbandAuthHandler(
            _mockAuthService.Object,
            _mockHttpContextAccessor.Object,
            Options.Create(csrfOptions));

        var claims = new[] { new Claim("userId", "test-user") };
        var httpContext = CreateAuthenticatedHttpContext(CookieAuthenticationDefaults.AuthenticationScheme, true, claims);
        httpContext.Request.Headers["X-CSRF-TOKEN"] = "some-token";

        var result = await InvokeTrySessionAuth(httpContext, handler);

        Assert.False(result);
    }
}
