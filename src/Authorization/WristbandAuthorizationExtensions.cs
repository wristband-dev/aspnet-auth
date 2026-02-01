using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Extension methods for registering Wristband authorization policies.
/// </summary>
public static class WristbandAuthorizationExtensions
{
    /// <summary>
    /// Registers the Wristband authorization handler.
    /// Required for all Wristband authorization policies (session, JWT, and multi-strategy).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for method chaining.</returns>
    public static IServiceCollection AddWristbandAuthorizationHandler(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthorizationHandler, WristbandAuthHandler>();
        return services;
    }

    /// <summary>
    /// Configures JWT Bearer authentication to use Wristband JWKS validation.
    /// Re-exported from aspnet-jwt for convenience.
    /// </summary>
    /// <param name="options">The JWT Bearer options to configure.</param>
    /// <param name="wristbandApplicationVanityDomain">
    /// The Wristband application vanity domain (e.g., "invotastic.us.wristband.dev").
    /// </param>
    /// <param name="jwksCacheMaxSize">
    /// Optional maximum number of JWKs to cache in memory. Defaults to 20.
    /// </param>
    /// <param name="jwksCacheTtl">
    /// Optional time-to-live for cached JWKs. If not set, keys remain in cache until eviction by size limit.
    /// </param>
    /// <returns>The JWT Bearer options for method chaining.</returns>
    public static JwtBearerOptions UseWristbandJwksValidation(
        this JwtBearerOptions options,
        string wristbandApplicationVanityDomain,
        int? jwksCacheMaxSize = null,
        TimeSpan? jwksCacheTtl = null)
        => Jwt.WristbandJwtBearerExtensions.UseWristbandJwksValidation(
            options,
            wristbandApplicationVanityDomain,
            jwksCacheMaxSize,
            jwksCacheTtl);

    /// <summary>
    /// Adds the "WristbandSession" authorization policy to the authorization options.
    /// Requires calling AddWristbandAuthorizationHandler() to register the authorization handler.
    /// </summary>
    /// <param name="options">The authorization options.</param>
    /// <returns>The authorization options for method chaining.</returns>
    public static AuthorizationOptions AddWristbandSessionPolicy(this AuthorizationOptions options)
    {
        options.AddPolicy("WristbandSession", policy =>
            policy.AddRequirements(new WristbandAuthRequirement(AuthStrategy.Session))
                  .AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme));

        return options;
    }

    /// <summary>
    /// Adds the "WristbandJwt" authorization policy to the authorization options.
    /// Requires calling AddWristbandAuthorizationHandler() to register the authorization handler.
    /// </summary>
    /// <param name="options">The authorization options.</param>
    /// <returns>The authorization options for method chaining.</returns>
    public static AuthorizationOptions AddWristbandJwtPolicy(this AuthorizationOptions options)
    {
        options.AddPolicy("WristbandJwt", policy =>
            policy.AddRequirements(new WristbandAuthRequirement(AuthStrategy.Jwt))
                  .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme));

        return options;
    }

    /// <summary>
    /// Adds both "WristbandSession" and "WristbandJwt" authorization policies.
    /// Convenience method for registering the most common Wristband policies.
    /// Requires calling AddWristbandAuthorizationHandler() to register the authorization handler.
    /// </summary>
    /// <param name="options">The authorization options.</param>
    /// <returns>The authorization options for method chaining.</returns>
    public static AuthorizationOptions AddWristbandDefaultPolicies(this AuthorizationOptions options)
    {
        options.AddWristbandSessionPolicy();
        options.AddWristbandJwtPolicy();
        return options;
    }

    /// <summary>
    /// Adds a multi-strategy Wristband authorization policy with configurable strategy priority.
    /// Requires calling AddWristbandAuthorizationHandler() to register the authorization handler.
    /// </summary>
    /// <param name="options">The authorization options.</param>
    /// <param name="strategies">Array of auth strategies in priority order (first is tried first).</param>
    /// <param name="policyName">Name of the policy (defaults to "WristbandMultiAuth").</param>
    /// <returns>The authorization options for method chaining.</returns>
    public static AuthorizationOptions AddWristbandMultiStrategyPolicy(
        this AuthorizationOptions options,
        AuthStrategy[] strategies,
        string policyName = "WristbandMultiAuth")
    {
        options.AddPolicy(policyName, policy =>
            policy.AddRequirements(new WristbandAuthRequirement(strategies))
                  .AddAuthenticationSchemes(
                      CookieAuthenticationDefaults.AuthenticationScheme,
                      JwtBearerDefaults.AuthenticationScheme));

        return options;
    }
}
