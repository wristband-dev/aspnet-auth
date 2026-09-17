using System.Net;
using System.Text.Json;

namespace Wristband.AspNet.Auth;

/// <summary>
/// Provides the shared retry policy applied to every REST API call made to the Wristband platform.
/// </summary>
internal static class WristbandApiRetry
{
    /// <summary>
    /// The maximum number of attempts made for a single Wristband API call, including the initial attempt.
    /// </summary>
    internal const int MaxApiRetryAttempts = 3;

    /// <summary>
    /// The delay before the first retry, in milliseconds.
    /// </summary>
    internal const int ApiRetryDelayMs = 100;

    /// <summary>
    /// The factor the retry delay is multiplied by after each attempt, producing exponential backoff.
    /// </summary>
    internal const int ApiRetryDelayMultiplier = 2;

    /// <summary>
    /// Invokes the given operation, retrying transient failures with exponential backoff.
    /// </summary>
    /// <typeparam name="T">The type returned by the operation.</typeparam>
    /// <param name="operation">The Wristband API call to invoke.</param>
    /// <returns>A task that represents the asynchronous operation and contains its result.</returns>
    internal static async Task<T> WithRetry<T>(Func<Task<T>> operation)
    {
        var delayMs = ApiRetryDelayMs;

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await operation();
            }
            catch (Exception error) when (attempt < MaxApiRetryAttempts && IsRetryableError(error))
            {
                await Task.Delay(delayMs);
                delayMs *= ApiRetryDelayMultiplier;
            }
        }
    }

    /// <summary>
    /// Invokes the given operation, retrying transient failures with exponential backoff.
    /// </summary>
    /// <param name="operation">The Wristband API call to invoke.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    internal static async Task WithRetry(Func<Task> operation)
    {
        await WithRetry<bool>(async () =>
        {
            await operation();
            return true;
        });
    }

    /// <summary>
    /// Determines whether a failed Wristband API call should be retried.
    /// </summary>
    /// <remarks>
    /// Only transient failures are retried: 5xx responses and network-level errors such as connection
    /// failures and timeouts. A 4xx response indicates a client-side problem that a retry cannot fix,
    /// and a malformed response body is not transient either, so neither is retried.
    /// </remarks>
    /// <param name="error">The exception thrown by the API call.</param>
    /// <returns>True if the error is transient and the call should be retried; otherwise, false.</returns>
    internal static bool IsRetryableError(Exception error)
    {
        // These are 4xx conditions the API client has already classified, so a retry cannot
        // change the outcome.
        if (error is InvalidGrantError)
        {
            return false;
        }

        if (error is WristbandError wristbandError)
        {
            return wristbandError.Error != "invalid_refresh_token";
        }

        if (error is HttpRequestException httpRequestException)
        {
            // A null status code means the request never produced a response at all (DNS failure,
            // connection reset, timeout), which is transient.
            var statusCode = httpRequestException.StatusCode;
            return statusCode is null || (int)statusCode >= (int)HttpStatusCode.InternalServerError;
        }

        // A response body that could not be parsed is a server-side contract problem, not a
        // transient one. Retrying it would also mean retrying a 4xx whose body happened to be an
        // HTML error page from a proxy or CDN rather than the expected JSON.
        if (error is JsonException || error is InvalidOperationException)
        {
            return false;
        }

        return true;
    }
}
