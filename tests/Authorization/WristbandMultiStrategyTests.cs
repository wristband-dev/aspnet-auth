using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

/// <summary>
/// Covers how the auth handler and the authorization result handler work together when more than one strategy is
/// configured: the first strategy whose credential is in the request decides the result.
/// </summary>
public class WristbandMultiStrategyTests
{
    private const string SessionCsrfToken = "session-csrf-token";

    private readonly Mock<IWristbandAuthService> _mockWristbandAuth = new();
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor = new();
    private readonly Mock<IAuthenticationService> _mockAuthenticationService = new();
    private readonly WristbandAuthHandler _handler;

    public WristbandMultiStrategyTests()
    {
        _handler = new WristbandAuthHandler(
            _mockWristbandAuth.Object,
            _mockHttpContextAccessor.Object,
            Options.Create(new WristbandCsrfOptions { EnableCsrfProtection = true, CsrfHeaderName = "X-CSRF-TOKEN" }));
    }

    public enum Outcome
    {
        Succeeded,
        Challenged,
        Forbidden,
    }

    public enum SessionState
    {
        None,
        Valid,
        CsrfWrong,
        Invalid,
    }

    public enum JwtState
    {
        None,
        Valid,
        Expired,
    }

    // Each row matches one in the aspnet-auth discrepancies table, plus the single-strategy cases.
    [Theory]
    [InlineData("SESSION,JWT", SessionState.CsrfWrong, JwtState.None, Outcome.Forbidden, WristbandAuthFailureReason.CsrfFailed)]
    [InlineData("SESSION,JWT", SessionState.None, JwtState.Valid, Outcome.Succeeded, null)]
    [InlineData("SESSION,JWT", SessionState.None, JwtState.Expired, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    [InlineData("SESSION,JWT", SessionState.CsrfWrong, JwtState.Valid, Outcome.Forbidden, WristbandAuthFailureReason.CsrfFailed)]
    [InlineData("JWT,SESSION", SessionState.Valid, JwtState.Expired, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    [InlineData("SESSION,JWT", SessionState.None, JwtState.None, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    [InlineData("JWT,SESSION", SessionState.None, JwtState.None, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    [InlineData("SESSION,JWT", SessionState.Invalid, JwtState.Valid, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    [InlineData("SESSION,JWT", SessionState.Valid, JwtState.Expired, Outcome.Succeeded, null)]
    [InlineData("SESSION", SessionState.Valid, JwtState.None, Outcome.Succeeded, null)]
    [InlineData("SESSION", SessionState.CsrfWrong, JwtState.None, Outcome.Forbidden, WristbandAuthFailureReason.CsrfFailed)]
    [InlineData("SESSION", SessionState.None, JwtState.Valid, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    [InlineData("JWT", SessionState.None, JwtState.Valid, Outcome.Succeeded, null)]
    [InlineData("JWT", SessionState.None, JwtState.Expired, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    [InlineData("JWT", SessionState.Valid, JwtState.None, Outcome.Challenged, WristbandAuthFailureReason.NotAuthenticated)]
    public async Task Strategies_UseTheFirstCredentialInTheRequest(
        string strategies,
        SessionState session,
        JwtState jwt,
        Outcome expectedOutcome,
        string? expectedReason)
    {
        var httpContext = CreateHttpContext(session, jwt);
        _mockWristbandAuth
            .Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ReturnsAsync((TokenData?)null);

        var (outcome, reason) = await Authorize(httpContext, ParseStrategies(strategies));

        Assert.Equal(expectedOutcome, outcome);
        Assert.Equal(expectedReason, reason);
    }

    [Fact]
    public async Task Session_WithFailedTokenRefresh_IsChallengedWithTokenRefreshFailed()
    {
        var httpContext = CreateHttpContext(SessionState.Valid, JwtState.Valid, sessionClaims: new[]
        {
            new Claim("refreshToken", "refresh-token"),
            new Claim("expiresAt", DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeMilliseconds().ToString()),
        });
        _mockWristbandAuth
            .Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ThrowsAsync(new WristbandError("invalid_refresh_token", "Invalid Refresh Token"));

        var (outcome, reason) = await Authorize(httpContext, AuthStrategy.Session, AuthStrategy.Jwt);

        Assert.Equal(Outcome.Challenged, outcome);
        Assert.Equal(WristbandAuthFailureReason.TokenRefreshFailed, reason);
    }

    [Fact]
    public async Task Jwt_WithoutAuthorizationHeader_IsNotValidated()
    {
        var httpContext = CreateHttpContext(SessionState.Valid, JwtState.None);

        await Authorize(httpContext, AuthStrategy.Session, AuthStrategy.Jwt);

        _mockAuthenticationService.Verify(
            x => x.AuthenticateAsync(It.IsAny<HttpContext>(), JwtBearerDefaults.AuthenticationScheme),
            Times.Never);
    }

    [Fact]
    public async Task Session_WithCsrfFailure_SetsCsrfFailureFlag()
    {
        var httpContext = CreateHttpContext(SessionState.CsrfWrong, JwtState.None);

        await Authorize(httpContext, AuthStrategy.Session);

        Assert.True((bool)httpContext.Items["WristbandCsrfFailure"]!);
    }

    [Fact]
    public async Task Session_UsesTheConfiguredSessionCookieName()
    {
        var httpContext = CreateHttpContext(SessionState.Valid, JwtState.None, sessionCookieName: "custom-session");
        _mockWristbandAuth
            .Setup(x => x.RefreshTokenIfExpired(It.IsAny<string>(), It.IsAny<long>()))
            .ReturnsAsync((TokenData?)null);

        var (outcome, _) = await Authorize(httpContext, AuthStrategy.Session);

        Assert.Equal(Outcome.Succeeded, outcome);
    }

    [Fact]
    public async Task ResultHandler_PassesNonWristbandFailuresToTheDefaultHandler()
    {
        var httpContext = CreateHttpContext(SessionState.None, JwtState.None);
        var resultHandler = new WristbandAuthorizationMiddlewareResultHandler();
        var policy = CreatePolicy(AuthStrategy.Session);

        await resultHandler.HandleAsync(_ => Task.CompletedTask, httpContext, policy, PolicyAuthorizationResult.Forbid());

        _mockAuthenticationService.Verify(
            x => x.ForbidAsync(httpContext, CookieAuthenticationDefaults.AuthenticationScheme, It.IsAny<AuthenticationProperties>()),
            Times.Once);
    }

    [Fact]
    public void AddWristbandAuthorizationHandler_ReplacesTheDefaultResultHandler()
    {
        var services = new ServiceCollection();
        services.AddAuthorization();
        services.AddWristbandAuthorizationHandler();

        var provider = services.BuildServiceProvider();

        Assert.IsType<WristbandAuthorizationMiddlewareResultHandler>(provider.GetRequiredService<IAuthorizationMiddlewareResultHandler>());
    }

    [Fact]
    public void AddWristbandAuthorizationHandler_BeforeAddAuthorization_StillReplacesTheDefaultResultHandler()
    {
        var services = new ServiceCollection();
        services.AddWristbandAuthorizationHandler();
        services.AddAuthorization();

        var provider = services.BuildServiceProvider();

        Assert.IsType<WristbandAuthorizationMiddlewareResultHandler>(provider.GetRequiredService<IAuthorizationMiddlewareResultHandler>());
    }

    [Fact]
    public void AddWristbandAuthorizationHandler_AfterAddAuthorization_RegistersTheAuthHandler()
    {
        var services = new ServiceCollection();
        services.AddAuthorization();
        services.AddWristbandAuthorizationHandler();
        services.AddSingleton(_mockWristbandAuth.Object);
        services.AddOptions();

        var provider = services.BuildServiceProvider();

        // Also resolves without the app registering IHttpContextAccessor itself.
        Assert.Contains(provider.GetServices<IAuthorizationHandler>(), h => h is WristbandAuthHandler);
    }

    [Fact]
    public void AddWristbandAuthorizationHandler_CalledTwice_RegistersTheAuthHandlerOnce()
    {
        var services = new ServiceCollection();
        services.AddWristbandAuthorizationHandler();
        services.AddWristbandAuthorizationHandler();

        Assert.Single(services, d => d.ServiceType == typeof(IAuthorizationHandler) && d.ImplementationType == typeof(WristbandAuthHandler));
    }

    private static AuthStrategy[] ParseStrategies(string strategies)
    {
        return strategies.Split(',').Select(s => s == "SESSION" ? AuthStrategy.Session : AuthStrategy.Jwt).ToArray();
    }

    private static AuthorizationPolicy CreatePolicy(params AuthStrategy[] strategies)
    {
        return new AuthorizationPolicyBuilder()
            .AddRequirements(new WristbandAuthRequirement(strategies))
            .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme, JwtBearerDefaults.AuthenticationScheme)
            .Build();
    }

    private async Task<(Outcome Outcome, string? Reason)> Authorize(HttpContext httpContext, params AuthStrategy[] strategies)
    {
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);
        var policy = CreatePolicy(strategies);
        var authContext = new AuthorizationHandlerContext(policy.Requirements, httpContext.User, null);

        await _handler.HandleAsync(authContext);

        var reason = authContext.FailureReasons.OfType<WristbandAuthFailureReason>().SingleOrDefault()?.Reason;
        var authorizeResult = authContext.HasSucceeded
            ? PolicyAuthorizationResult.Success()
            : PolicyAuthorizationResult.Forbid(AuthorizationFailure.Failed(authContext.FailureReasons));

        var nextCalled = false;
        await new WristbandAuthorizationMiddlewareResultHandler().HandleAsync(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            httpContext,
            policy,
            authorizeResult);

        var forbidden = _mockAuthenticationService.Invocations.Any(i => i.Method.Name == nameof(IAuthenticationService.ForbidAsync));
        var challenged = _mockAuthenticationService.Invocations.Any(i => i.Method.Name == nameof(IAuthenticationService.ChallengeAsync));
        var outcome = nextCalled ? Outcome.Succeeded : forbidden ? Outcome.Forbidden : challenged ? Outcome.Challenged : throw new InvalidOperationException("No response was chosen");
        return (outcome, reason);
    }

    private HttpContext CreateHttpContext(
        SessionState session,
        JwtState jwt,
        Claim[]? sessionClaims = null,
        string sessionCookieName = "session")
    {
        var httpContext = new DefaultHttpContext();

        var sessionPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            (sessionClaims ?? Array.Empty<Claim>()).Append(new Claim("csrf_token", SessionCsrfToken)),
            CookieAuthenticationDefaults.AuthenticationScheme));
        _mockAuthenticationService
            .Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), CookieAuthenticationDefaults.AuthenticationScheme))
            .ReturnsAsync(session is SessionState.Valid or SessionState.CsrfWrong
                ? AuthenticateResult.Success(new AuthenticationTicket(sessionPrincipal, CookieAuthenticationDefaults.AuthenticationScheme))
                : AuthenticateResult.Fail("Invalid session"));

        var jwtPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", "jwt-user") }, JwtBearerDefaults.AuthenticationScheme));
        _mockAuthenticationService
            .Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), JwtBearerDefaults.AuthenticationScheme))
            .ReturnsAsync(jwt == JwtState.Valid
                ? AuthenticateResult.Success(new AuthenticationTicket(jwtPrincipal, JwtBearerDefaults.AuthenticationScheme))
                : AuthenticateResult.Fail("Token expired"));

        var services = new ServiceCollection();
        services.AddSingleton(_mockAuthenticationService.Object);
        services.AddOptions();
        services.Configure<CookieAuthenticationOptions>(
            CookieAuthenticationDefaults.AuthenticationScheme,
            options => options.Cookie.Name = sessionCookieName);
        httpContext.RequestServices = services.BuildServiceProvider();

        // Like the auth handler, the session strategy reads the session's claims from HttpContext.User.
        if (session is SessionState.Valid or SessionState.CsrfWrong)
        {
            httpContext.User = sessionPrincipal;
        }

        if (session != SessionState.None)
        {
            httpContext.Request.Headers.Cookie = $"{sessionCookieName}=session-value";
            httpContext.Request.Headers["X-CSRF-TOKEN"] = session == SessionState.CsrfWrong ? "wrong-token" : SessionCsrfToken;
        }

        if (jwt != JwtState.None)
        {
            httpContext.Request.Headers.Authorization = "Bearer jwt-token";
        }

        return httpContext;
    }
}
