using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandAuthorizationExtensionsTests
{
    [Fact]
    public void AddWristbandAuthorizationHandler_RegistersHandler()
    {
        var services = new ServiceCollection();
        services.AddWristbandAuthorizationHandler();

        var descriptor = services.FirstOrDefault(d =>
            d.ServiceType == typeof(IAuthorizationHandler) &&
            d.ImplementationType == typeof(WristbandAuthHandler));

        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
    }

    [Fact]
    public void AddWristbandAuthorizationHandler_ReturnsServiceCollection()
    {
        var services = new ServiceCollection();
        var result = services.AddWristbandAuthorizationHandler();
        Assert.Same(services, result);
    }

    [Fact]
    public void AddWristbandAuthorizationHandler_CanBeCalledMultipleTimes()
    {
        var services = new ServiceCollection();
        services.AddWristbandAuthorizationHandler();
        services.AddWristbandAuthorizationHandler();

        var descriptors = services.Where(d =>
            d.ServiceType == typeof(IAuthorizationHandler) &&
            d.ImplementationType == typeof(WristbandAuthHandler));

        Assert.Single(descriptors);
    }

    [Fact]
    public void AddWristbandSessionPolicy_RegistersPolicy()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandSessionPolicy();
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var policy = authOptions.Value.GetPolicy("WristbandSession");

        Assert.NotNull(policy);
        Assert.Contains(CookieAuthenticationDefaults.AuthenticationScheme, policy.AuthenticationSchemes);
        Assert.Contains(policy.Requirements, r => r is WristbandAuthRequirement);
    }

    [Fact]
    public void AddWristbandSessionPolicy_ReturnsAuthorizationOptions()
    {
        var options = new AuthorizationOptions();
        var result = options.AddWristbandSessionPolicy();
        Assert.Same(options, result);
    }

    [Fact]
    public void AddWristbandJwtPolicy_RegistersPolicy()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandJwtPolicy();
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var policy = authOptions.Value.GetPolicy("WristbandJwt");

        Assert.NotNull(policy);
        Assert.Contains(JwtBearerDefaults.AuthenticationScheme, policy.AuthenticationSchemes);
        Assert.Contains(policy.Requirements, r => r is WristbandAuthRequirement);
    }

    [Fact]
    public void AddWristbandJwtPolicy_ReturnsAuthorizationOptions()
    {
        var options = new AuthorizationOptions();
        var result = options.AddWristbandJwtPolicy();
        Assert.Same(options, result);
    }

    [Fact]
    public void AddWristbandDefaultPolicies_RegistersBothPolicies()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandDefaultPolicies();
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var sessionPolicy = authOptions.Value.GetPolicy("WristbandSession");
        var jwtPolicy = authOptions.Value.GetPolicy("WristbandJwt");

        Assert.NotNull(sessionPolicy);
        Assert.NotNull(jwtPolicy);
    }

    [Fact]
    public void AddWristbandDefaultPolicies_ReturnsAuthorizationOptions()
    {
        var options = new AuthorizationOptions();
        var result = options.AddWristbandDefaultPolicies();
        Assert.Same(options, result);
    }

    [Fact]
    public void AddWristbandMultiStrategyPolicy_WithDefaultName_RegistersPolicy()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandMultiStrategyPolicy(new[] { AuthStrategy.Session, AuthStrategy.Jwt });
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var policy = authOptions.Value.GetPolicy("WristbandMultiAuth");

        Assert.NotNull(policy);
        Assert.Contains(CookieAuthenticationDefaults.AuthenticationScheme, policy.AuthenticationSchemes);
        Assert.Contains(JwtBearerDefaults.AuthenticationScheme, policy.AuthenticationSchemes);
        Assert.Contains(policy.Requirements, r => r is WristbandAuthRequirement);
    }

    [Fact]
    public void AddWristbandMultiStrategyPolicy_WithCustomName_RegistersPolicy()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandMultiStrategyPolicy(
                new[] { AuthStrategy.Session, AuthStrategy.Jwt },
                policyName: "CustomPolicy");
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var policy = authOptions.Value.GetPolicy("CustomPolicy");

        Assert.NotNull(policy);
    }

    [Fact]
    public void AddWristbandMultiStrategyPolicy_WithSingleStrategy_RegistersPolicy()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandMultiStrategyPolicy(new[] { AuthStrategy.Session });
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var policy = authOptions.Value.GetPolicy("WristbandMultiAuth");

        Assert.NotNull(policy);
        Assert.Contains(policy.Requirements, r => r is WristbandAuthRequirement req && req.Strategies.Length == 1);
    }

    [Fact]
    public void AddWristbandMultiStrategyPolicy_ReturnsAuthorizationOptions()
    {
        var options = new AuthorizationOptions();
        var result = options.AddWristbandMultiStrategyPolicy(new[] { AuthStrategy.Session, AuthStrategy.Jwt });
        Assert.Same(options, result);
    }

    [Fact]
    public void UseWristbandJwksValidation_DelegatesToJwtPackage()
    {
        var options = new JwtBearerOptions();
        var result = options.UseWristbandJwksValidation(
            wristbandApplicationVanityDomain: "test.wristband.dev",
            jwksCacheMaxSize: 10,
            jwksCacheTtl: TimeSpan.FromHours(1));

        Assert.Same(options, result);
        Assert.NotNull(options.TokenValidationParameters);
    }

    [Fact]
    public void AddWristbandSessionPolicy_CreatesRequirementWithSessionStrategy()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandSessionPolicy();
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var policy = authOptions.Value.GetPolicy("WristbandSession");
        var requirement = policy?.Requirements.OfType<WristbandAuthRequirement>().FirstOrDefault();

        Assert.NotNull(requirement);
        Assert.Single(requirement.Strategies);
        Assert.Equal(AuthStrategy.Session, requirement.Strategies[0]);
    }

    [Fact]
    public void AddWristbandJwtPolicy_CreatesRequirementWithJwtStrategy()
    {
        var services = new ServiceCollection();
        services.AddAuthorization(options =>
        {
            options.AddWristbandJwtPolicy();
        });

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthorizationOptions>>();
        var policy = authOptions.Value.GetPolicy("WristbandJwt");
        var requirement = policy?.Requirements.OfType<WristbandAuthRequirement>().FirstOrDefault();

        Assert.NotNull(requirement);
        Assert.Single(requirement.Strategies);
        Assert.Equal(AuthStrategy.Jwt, requirement.Strategies[0]);
    }
}
