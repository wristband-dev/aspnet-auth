using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandSessionMiddlewareTests
{
    private readonly Mock<RequestDelegate> _mockNext;
    private readonly WristbandCsrfOptions _csrfOptions;
    private readonly CookieAuthenticationOptions _cookieOptions;
    private readonly Mock<IOptionsMonitor<CookieAuthenticationOptions>> _mockCookieOptionsMonitor;

    public WristbandSessionMiddlewareTests()
    {
        _mockNext = new Mock<RequestDelegate>();
        _csrfOptions = new WristbandCsrfOptions();
        _cookieOptions = new CookieAuthenticationOptions();

        _mockCookieOptionsMonitor = new Mock<IOptionsMonitor<CookieAuthenticationOptions>>();
        _mockCookieOptionsMonitor
            .Setup(x => x.Get(CookieAuthenticationDefaults.AuthenticationScheme))
            .Returns(_cookieOptions);
    }

    private WristbandSessionMiddleware CreateMiddleware(WristbandCsrfOptions? csrfOptions = null)
    {
        return new WristbandSessionMiddleware(
            _mockNext.Object,
            Options.Create(csrfOptions ?? _csrfOptions),
            _mockCookieOptionsMonitor.Object);
    }

    private HttpContext CreateHttpContext()
    {
        var context = new DefaultHttpContext();
        var mockAuthService = new Mock<IAuthenticationService>();

        mockAuthService
            .Setup(x => x.SignInAsync(
                It.IsAny<HttpContext>(),
                It.IsAny<string>(),
                It.IsAny<ClaimsPrincipal>(),
                It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);

        mockAuthService
            .Setup(x => x.SignOutAsync(
                It.IsAny<HttpContext>(),
                It.IsAny<string>(),
                It.IsAny<AuthenticationProperties>()))
            .Returns(Task.CompletedTask);

        var services = new ServiceCollection();
        services.AddSingleton(mockAuthService.Object);
        context.RequestServices = services.BuildServiceProvider();

        return context;
    }

    [Fact]
    public async Task InvokeAsync_CallsNextMiddleware()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();

        await middleware.InvokeAsync(context);

        _mockNext.Verify(x => x(context), Times.Once);
    }

    [Fact]
    public void CreateCsrfToken_Returns32CharacterHexString()
    {
        var middleware = CreateMiddleware();

        var token = middleware.CreateCsrfToken();

        Assert.Equal(32, token.Length);
        Assert.Matches("^[a-f0-9]{32}$", token);
    }

    [Fact]
    public void CreateCsrfToken_GeneratesUniqueTokens()
    {
        var middleware = CreateMiddleware();

        var token1 = middleware.CreateCsrfToken();
        var token2 = middleware.CreateCsrfToken();

        Assert.NotEqual(token1, token2);
    }

    [Fact]
    public void AddCsrfTokenToSession_AddsCsrfTokenClaim()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        var claims = new[] { new Claim("userId", "user123") };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);

        middleware.AddCsrfTokenToSession(context, "test-token");

        var csrfToken = context.User.FindFirst("csrf_token")?.Value;
        Assert.Equal("test-token", csrfToken);
    }

    [Fact]
    public void AddCsrfTokenToSession_PreservesExistingClaims()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        var claims = new[] { new Claim("userId", "user123") };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);

        middleware.AddCsrfTokenToSession(context, "test-token");

        var userId = context.User.FindFirst("userId")?.Value;
        Assert.Equal("user123", userId);
    }

    [Fact]
    public void UpdateCsrfCookie_SetsCookieWithToken()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-csrf-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains("CSRF-TOKEN=test-csrf-token", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_IsNotHttpOnly()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.DoesNotContain("httponly", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_UsesCustomDomain()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN",
            CsrfCookieDomain = ".example.com"
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.Contains("domain=.example.com", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_UsesSessionCookieDomainWhenNotSpecified()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.Domain = ".session-domain.com";
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.Contains("domain=.session-domain.com", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_SecurePolicyAlways_IsSecure()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.Contains("secure", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_SecurePolicyNone_IsNotSecure()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.None;
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.DoesNotContain("secure", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_SecurePolicySameAsRequest_HttpsIsSecure()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        context.Request.Scheme = "https";

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.Contains("secure", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_SecurePolicySameAsRequest_HttpIsNotSecure()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        context.Request.Scheme = "http";

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.DoesNotContain("secure", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_SameSiteLax()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.SameSite = SameSiteMode.Lax;
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.Contains("samesite=lax", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_SameSiteStrict()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.SameSite = SameSiteMode.Strict;
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.Contains("samesite=strict", cookies);
    }

    [Fact]
    public void UpdateCsrfCookie_SameSiteUnspecified_DefaultsToLax()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        _cookieOptions.Cookie.SameSite = SameSiteMode.Unspecified;
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        middleware.UpdateCsrfCookie(context, "test-token");

        var cookies = context.Response.Headers["Set-Cookie"].ToString().ToLower();
        Assert.Contains("samesite=lax", cookies);
    }

    [Fact]
    public void HandleCsrfTokenGeneration_GeneratesNewTokenWhenMissing()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        var claims = new[] { new Claim("userId", "user123") };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);

        middleware.HandleCsrfTokenGeneration(context);

        var csrfToken = context.User.FindFirst("csrf_token")?.Value;
        Assert.NotNull(csrfToken);
        Assert.Equal(32, csrfToken.Length);
    }

    [Fact]
    public void HandleCsrfTokenGeneration_ReusesExistingToken()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        var existingToken = "existing-csrf-token-123";
        var claims = new[]
        {
            new Claim("userId", "user123"),
            new Claim("csrf_token", existingToken)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);

        middleware.HandleCsrfTokenGeneration(context);

        var csrfToken = context.User.FindFirst("csrf_token")?.Value;
        Assert.Equal(existingToken, csrfToken);
    }

    [Fact]
    public void HandleCsrfFailureStatusCode_Converts401To403()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        context.Response.StatusCode = 401;
        context.Items["WristbandCsrfFailure"] = true;

        middleware.HandleCsrfFailureStatusCode(context);

        Assert.Equal(403, context.Response.StatusCode);
    }

    [Fact]
    public void HandleCsrfFailureStatusCode_DoesNotConvertWhenCsrfDisabled()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        context.Response.StatusCode = 401;
        context.Items["WristbandCsrfFailure"] = true;

        middleware.HandleCsrfFailureStatusCode(context);

        Assert.Equal(401, context.Response.StatusCode);
    }

    [Fact]
    public void HandleCsrfFailureStatusCode_DoesNotConvertWhenFlagMissing()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        context.Response.StatusCode = 401;

        middleware.HandleCsrfFailureStatusCode(context);

        Assert.Equal(401, context.Response.StatusCode);
    }

    [Fact]
    public void HandleCsrfFailureStatusCode_DoesNotConvertNon401StatusCodes()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        context.Response.StatusCode = 404;
        context.Items["WristbandCsrfFailure"] = true;

        middleware.HandleCsrfFailureStatusCode(context);

        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task HandleSessionDeletion_SignsOutUser()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        var authService = context.RequestServices.GetService<IAuthenticationService>() as Mock<IAuthenticationService>;

        await middleware.HandleSessionDeletion(context);

        authService?.Verify(x => x.SignOutAsync(
            context,
            CookieAuthenticationDefaults.AuthenticationScheme,
            It.IsAny<AuthenticationProperties>()), Times.Once);
    }

    [Fact]
    public async Task HandleSessionDeletion_DeletesCsrfCookieWhenEnabled()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();

        await middleware.HandleSessionDeletion(context);

        var cookies = context.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains("CSRF-TOKEN", cookies);
        Assert.Contains("expires=", cookies);
    }

    [Fact]
    public async Task HandleSessionDeletion_DoesNotDeleteCsrfCookieWhenDisabled()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();

        await middleware.HandleSessionDeletion(context);

        var cookies = context.Response.Headers["Set-Cookie"].ToString();
        Assert.DoesNotContain("CSRF-TOKEN", cookies);
    }

    [Fact]
    public async Task HandleSessionSave_SignsInUser()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        var claims = new[] { new Claim("userId", "user123") };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);
        var authService = context.RequestServices.GetService<IAuthenticationService>() as Mock<IAuthenticationService>;

        await middleware.HandleSessionSave(context);

        authService?.Verify(x => x.SignInAsync(
            context,
            CookieAuthenticationDefaults.AuthenticationScheme,
            It.IsAny<ClaimsPrincipal>(),
            It.Is<AuthenticationProperties>(p => p.IsPersistent)), Times.Once);
    }

    [Fact]
    public async Task HandleSessionSave_GeneratesCsrfTokenWhenEnabled()
    {
        var csrfOptions = new WristbandCsrfOptions
        {
            EnableCsrfProtection = true,
            CsrfCookieName = "CSRF-TOKEN"
        };
        var middleware = CreateMiddleware(csrfOptions);
        var context = CreateHttpContext();
        var claims = new[] { new Claim("userId", "user123") };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);

        await middleware.HandleSessionSave(context);

        var csrfToken = context.User.FindFirst("csrf_token")?.Value;
        Assert.NotNull(csrfToken);
    }

    [Fact]
    public async Task CommitSessionAsync_DeletesTakesPriorityOverSave()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        context.Items["WristbandSessionNeedsDelete"] = true;
        context.Items["WristbandSessionNeedsSave"] = true;
        var authService = context.RequestServices.GetService<IAuthenticationService>() as Mock<IAuthenticationService>;

        await middleware.CommitSessionAsync(context);

        authService?.Verify(x => x.SignOutAsync(
            It.IsAny<HttpContext>(),
            It.IsAny<string>(),
            It.IsAny<AuthenticationProperties>()), Times.Once);

        authService?.Verify(x => x.SignInAsync(
            It.IsAny<HttpContext>(),
            It.IsAny<string>(),
            It.IsAny<ClaimsPrincipal>(),
            It.IsAny<AuthenticationProperties>()), Times.Never);
    }

    [Fact]
    public async Task CommitSessionAsync_SavesSessionWhenFlagSet()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        var claims = new[] { new Claim("userId", "user123") };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);
        context.Items["WristbandSessionNeedsSave"] = true;
        var authService = context.RequestServices.GetService<IAuthenticationService>() as Mock<IAuthenticationService>;

        await middleware.CommitSessionAsync(context);

        authService?.Verify(x => x.SignInAsync(
            It.IsAny<HttpContext>(),
            It.IsAny<string>(),
            It.IsAny<ClaimsPrincipal>(),
            It.IsAny<AuthenticationProperties>()), Times.Once);
    }

    [Fact]
    public async Task CommitSessionAsync_DoesNothingWhenNoFlagsSet()
    {
        var middleware = CreateMiddleware();
        var context = CreateHttpContext();
        var authService = context.RequestServices.GetService<IAuthenticationService>() as Mock<IAuthenticationService>;

        await middleware.CommitSessionAsync(context);

        authService?.Verify(x => x.SignInAsync(
            It.IsAny<HttpContext>(),
            It.IsAny<string>(),
            It.IsAny<ClaimsPrincipal>(),
            It.IsAny<AuthenticationProperties>()), Times.Never);

        authService?.Verify(x => x.SignOutAsync(
            It.IsAny<HttpContext>(),
            It.IsAny<string>(),
            It.IsAny<AuthenticationProperties>()), Times.Never);
    }
}
