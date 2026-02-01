using Microsoft.AspNetCore.Authorization;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandAuthRequirementTests
{
    [Fact]
    public void Constructor_WithSingleStrategy_SetsStrategies()
    {
        var requirement = new WristbandAuthRequirement(AuthStrategy.Session);

        Assert.Single(requirement.Strategies);
        Assert.Equal(AuthStrategy.Session, requirement.Strategies[0]);
    }

    [Fact]
    public void Constructor_WithMultipleStrategies_SetsStrategiesInOrder()
    {
        var requirement = new WristbandAuthRequirement(AuthStrategy.Session, AuthStrategy.Jwt);

        Assert.Equal(2, requirement.Strategies.Length);
        Assert.Equal(AuthStrategy.Session, requirement.Strategies[0]);
        Assert.Equal(AuthStrategy.Jwt, requirement.Strategies[1]);
    }

    [Fact]
    public void Constructor_WithNoStrategies_ThrowsArgumentException()
    {
        var exception = Assert.Throws<ArgumentException>(() => new WristbandAuthRequirement());

        Assert.Contains("At least one authentication strategy must be specified", exception.Message);
        Assert.Equal("strategies", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithNullStrategies_ThrowsArgumentException()
    {
        var exception = Assert.Throws<ArgumentException>(() => new WristbandAuthRequirement(null!));

        Assert.Contains("At least one authentication strategy must be specified", exception.Message);
        Assert.Equal("strategies", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithDuplicateStrategies_ThrowsArgumentException()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            new WristbandAuthRequirement(AuthStrategy.Session, AuthStrategy.Jwt, AuthStrategy.Session));

        Assert.Contains("Duplicate authentication strategies are not allowed", exception.Message);
        Assert.Equal("strategies", exception.ParamName);
    }

    [Fact]
    public void Constructor_WithAllDuplicates_ThrowsArgumentException()
    {
        var exception = Assert.Throws<ArgumentException>(() =>
            new WristbandAuthRequirement(AuthStrategy.Jwt, AuthStrategy.Jwt, AuthStrategy.Jwt));

        Assert.Contains("Duplicate authentication strategies are not allowed", exception.Message);
        Assert.Equal("strategies", exception.ParamName);
    }

    [Fact]
    public void Strategies_ReturnsArrayOfStrategies()
    {
        var requirement = new WristbandAuthRequirement(AuthStrategy.Jwt, AuthStrategy.Session);

        var strategies = requirement.Strategies;

        Assert.NotNull(strategies);
        Assert.Equal(2, strategies.Length);
    }

    [Fact]
    public void Requirement_ImplementsIAuthorizationRequirement()
    {
        var requirement = new WristbandAuthRequirement(AuthStrategy.Session);

        Assert.IsAssignableFrom<IAuthorizationRequirement>(requirement);
    }

    [Fact]
    public void Constructor_PreservesStrategyOrder()
    {
        var requirement = new WristbandAuthRequirement(AuthStrategy.Jwt, AuthStrategy.Session);

        Assert.Equal(AuthStrategy.Jwt, requirement.Strategies[0]);
        Assert.Equal(AuthStrategy.Session, requirement.Strategies[1]);
    }
}
