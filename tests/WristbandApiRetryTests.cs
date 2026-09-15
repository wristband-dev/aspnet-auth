using System.Diagnostics;
using System.Net;
using System.Text.Json;

namespace Wristband.AspNet.Auth.Tests;

public class WristbandApiRetryTests
{
    // ////////////////////////////////////
    //  RETRY CLASSIFICATION TESTS
    // ////////////////////////////////////

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public void IsRetryableError_WithServerError_ReturnsTrue(HttpStatusCode statusCode)
    {
        var error = new HttpRequestException("Server error", null, statusCode);

        Assert.True(WristbandApiRetry.IsRetryableError(error));
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public void IsRetryableError_WithClientError_ReturnsFalse(HttpStatusCode statusCode)
    {
        var error = new HttpRequestException("Client error", null, statusCode);

        Assert.False(WristbandApiRetry.IsRetryableError(error));
    }

    // A request that never produced a response at all (DNS failure, connection reset, timeout)
    // carries no status code and is transient.
    [Fact]
    public void IsRetryableError_WithNetworkError_ReturnsTrue()
    {
        Assert.True(WristbandApiRetry.IsRetryableError(new HttpRequestException("Connection refused")));
        Assert.True(WristbandApiRetry.IsRetryableError(new TaskCanceledException("Timed out")));
    }

    [Fact]
    public void IsRetryableError_WithInvalidGrantError_ReturnsFalse()
    {
        Assert.False(WristbandApiRetry.IsRetryableError(new InvalidGrantError("The code expired")));
    }

    [Fact]
    public void IsRetryableError_WithInvalidRefreshToken_ReturnsFalse()
    {
        var error = new WristbandError("invalid_refresh_token", "Invalid Refresh Token");

        Assert.False(WristbandApiRetry.IsRetryableError(error));
    }

    [Fact]
    public void IsRetryableError_WithUnexpectedWristbandError_ReturnsTrue()
    {
        var error = new WristbandError("unexpected_error", "Server error occurred. Retry later.");

        Assert.True(WristbandApiRetry.IsRetryableError(error));
    }

    // A response body that could not be parsed is a server-side contract problem, not a transient
    // one, so retrying it would not help.
    [Fact]
    public void IsRetryableError_WithParseError_ReturnsFalse()
    {
        Assert.False(WristbandApiRetry.IsRetryableError(new JsonException("Unexpected token")));
        Assert.False(WristbandApiRetry.IsRetryableError(new InvalidOperationException("Failed to deserialize")));
    }

    // ////////////////////////////////////
    //  RETRY BEHAVIOR TESTS
    // ////////////////////////////////////

    [Fact]
    public async Task WithRetry_WhenOperationSucceeds_DoesNotRetry()
    {
        var attempts = 0;

        var result = await WristbandApiRetry.WithRetry(() =>
        {
            attempts++;
            return Task.FromResult("ok");
        });

        Assert.Equal("ok", result);
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task WithRetry_WhenTransientFailureRecovers_ReturnsResult()
    {
        var attempts = 0;

        var result = await WristbandApiRetry.WithRetry(() =>
        {
            attempts++;
            if (attempts < 3)
            {
                throw new HttpRequestException("Server error", null, HttpStatusCode.ServiceUnavailable);
            }

            return Task.FromResult("ok");
        });

        Assert.Equal("ok", result);
        Assert.Equal(3, attempts);
    }

    [Fact]
    public async Task WithRetry_WhenTransientFailurePersists_ThrowsAfterMaxAttempts()
    {
        var attempts = 0;

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            WristbandApiRetry.WithRetry<string>(() =>
            {
                attempts++;
                throw new HttpRequestException("Server error", null, HttpStatusCode.InternalServerError);
            }));

        Assert.Equal(WristbandApiRetry.MaxApiRetryAttempts, attempts);
    }

    [Fact]
    public async Task WithRetry_WithNonRetryableError_ThrowsImmediately()
    {
        var attempts = 0;

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            WristbandApiRetry.WithRetry<string>(() =>
            {
                attempts++;
                throw new HttpRequestException("Bad request", null, HttpStatusCode.BadRequest);
            }));

        Assert.Equal(1, attempts);
    }

    // The delay doubles after each failed attempt, so two retries wait 100ms and then 200ms.
    [Fact]
    public async Task WithRetry_BacksOffExponentially()
    {
        var stopwatch = Stopwatch.StartNew();

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            WristbandApiRetry.WithRetry<string>(() =>
                throw new HttpRequestException("Server error", null, HttpStatusCode.InternalServerError)));

        stopwatch.Stop();

        var expectedDelayMs = WristbandApiRetry.ApiRetryDelayMs +
            (WristbandApiRetry.ApiRetryDelayMs * WristbandApiRetry.ApiRetryDelayMultiplier);
        Assert.True(
            stopwatch.ElapsedMilliseconds >= expectedDelayMs,
            $"Expected at least {expectedDelayMs}ms of backoff, but only {stopwatch.ElapsedMilliseconds}ms elapsed.");
    }

    [Fact]
    public async Task WithRetry_NonGeneric_RetriesTransientFailures()
    {
        var attempts = 0;

        await WristbandApiRetry.WithRetry(() =>
        {
            attempts++;
            if (attempts < 2)
            {
                throw new HttpRequestException("Server error", null, HttpStatusCode.BadGateway);
            }

            return Task.CompletedTask;
        });

        Assert.Equal(2, attempts);
    }
}
