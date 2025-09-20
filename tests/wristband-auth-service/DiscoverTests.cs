using System.Reflection;

using Moq;

namespace Wristband.AspNet.Auth.Tests;

public class DiscoverTests
{
    private readonly Mock<IWristbandApiClient> _mockApiClient = new Mock<IWristbandApiClient>();

    [Fact]
    public async Task Discover_Should_ThrowWristbandError_When_AutoConfigureDisabled()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            LoginUrl = "https://example.com/login",
            RedirectUri = "https://example.com/callback",
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = false, // Disabled
        };

        var service = new WristbandAuthService(authConfig);

        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => service.Discover()
        );

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Equal("Cannot preload configs when AutoConfigureEnabled is false. Set AutoConfigureEnabled to true.", exception.ErrorDescription);
    }

    [Fact]
    public async Task Discover_Should_CallPreloadConfig_When_AutoConfigureEnabled()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = true, // Enabled
        };

        // Mock the API client to return a valid SDK configuration
        _mockApiClient
            .Setup(m => m.GetSdkConfiguration())
            .ReturnsAsync(new SdkConfiguration
            {
                LoginUrl = "https://example.com/login",
                RedirectUri = "https://example.com/callback",
                IsApplicationCustomDomainActive = false,
                CustomApplicationLoginPageUrl = null,
                LoginUrlTenantDomainSuffix = null
            });

        var service = CreateServiceWithMockedApiClient(authConfig);

        // This should complete without throwing an exception
        await service.Discover();

        // Verify that the SDK configuration was fetched (indicating PreloadConfig was called)
        _mockApiClient.Verify(m => m.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task Discover_Should_DefaultToTrue_When_AutoConfigureNotSpecified()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            WristbandApplicationVanityDomain = "example.com",
            // AutoConfigureEnabled not specified, should default to true
        };

        // Mock the API client to return a valid SDK configuration
        _mockApiClient
            .Setup(m => m.GetSdkConfiguration())
            .ReturnsAsync(new SdkConfiguration
            {
                LoginUrl = "https://example.com/login",
                RedirectUri = "https://example.com/callback",
                IsApplicationCustomDomainActive = false,
                CustomApplicationLoginPageUrl = null,
                LoginUrlTenantDomainSuffix = null
            });

        var service = CreateServiceWithMockedApiClient(authConfig);

        // This should complete without throwing an exception since AutoConfigureEnabled defaults to true
        await service.Discover();

        // Verify that the SDK configuration was fetched
        _mockApiClient.Verify(m => m.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task Discover_Should_PropagateConfigResolverExceptions()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = true,
        };

        // Mock the API client to throw an exception during SDK config fetch
        var expectedError = new WristbandError("config_fetch_error", "Failed to fetch configuration");
        _mockApiClient
            .Setup(m => m.GetSdkConfiguration())
            .ThrowsAsync(expectedError);

        var service = CreateServiceWithMockedApiClient(authConfig);

        // The exception from ConfigResolver.PreloadConfig should be propagated
        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => service.Discover()
        );

        // Should be the original error wrapped by ConfigResolver logic
        Assert.Contains("Failed to fetch SDK configuration", exception.ErrorDescription);
    }

    [Fact]
    public async Task Discover_Should_HandleNetworkErrors()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = true,
        };

        // Mock the API client to throw a network-related exception
        _mockApiClient
            .Setup(m => m.GetSdkConfiguration())
            .ThrowsAsync(new HttpRequestException("Network error"));

        var service = CreateServiceWithMockedApiClient(authConfig);

        // Should propagate as a WristbandError due to ConfigResolver's error handling
        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => service.Discover()
        );

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Contains("Failed to fetch SDK configuration", exception.ErrorDescription);
        Assert.Contains("Network error", exception.ErrorDescription);
    }

    [Fact]
    public async Task Discover_Should_CacheConfiguration_OnSuccessfulCall()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = true,
        };

        // Mock the API client to return a valid SDK configuration
        _mockApiClient
            .Setup(m => m.GetSdkConfiguration())
            .ReturnsAsync(new SdkConfiguration
            {
                LoginUrl = "https://example.com/login",
                RedirectUri = "https://example.com/callback",
                IsApplicationCustomDomainActive = false,
                CustomApplicationLoginPageUrl = null,
                LoginUrlTenantDomainSuffix = null
            });

        var service = CreateServiceWithMockedApiClient(authConfig);

        // Call Discover twice
        await service.Discover();
        await service.Discover();

        // Verify that the SDK configuration was only fetched once (due to caching)
        _mockApiClient.Verify(m => m.GetSdkConfiguration(), Times.Once);
    }

    [Fact]
    public async Task Discover_Should_HandleInvalidSdkConfigurationResponse()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = true,
        };

        // Mock the API client to return an invalid SDK configuration (missing required fields)
        _mockApiClient
            .Setup(m => m.GetSdkConfiguration())
            .ReturnsAsync(new SdkConfiguration
            {
                IsApplicationCustomDomainActive = false,
                CustomApplicationLoginPageUrl = null,
                LoginUrlTenantDomainSuffix = null
            });

        var service = CreateServiceWithMockedApiClient(authConfig);

        // Should throw a validation error
        var exception = await Assert.ThrowsAsync<WristbandError>(
            () => service.Discover()
        );

        Assert.Equal("sdk_config_error", exception.Error);
        Assert.Contains("missing required field", exception.ErrorDescription);
    }

    [Fact]
    public async Task Discover_Should_HandleMultipleFailuresWithRetry()
    {
        var authConfig = new WristbandAuthConfig
        {
            ClientId = "valid-client-id",
            ClientSecret = "valid-client-secret",
            LoginStateSecret = new string('a', 32),
            WristbandApplicationVanityDomain = "example.com",
            AutoConfigureEnabled = true,
        };

        // Mock the API client to fail twice, then succeed
        _mockApiClient
            .SetupSequence(m => m.GetSdkConfiguration())
            .ThrowsAsync(new HttpRequestException("Temporary failure"))
            .ThrowsAsync(new HttpRequestException("Another failure"))
            .ReturnsAsync(new SdkConfiguration
            {
                LoginUrl = "https://example.com/login",
                RedirectUri = "https://example.com/callback",
                IsApplicationCustomDomainActive = false,
                CustomApplicationLoginPageUrl = null,
                LoginUrlTenantDomainSuffix = null
            });

        var service = CreateServiceWithMockedApiClient(authConfig);

        // Should succeed after retries
        await service.Discover();

        // Verify that multiple attempts were made
        _mockApiClient.Verify(m => m.GetSdkConfiguration(), Times.Exactly(3));
    }

    private WristbandAuthService CreateServiceWithMockedApiClient(WristbandAuthConfig authConfig)
    {
        var service = new WristbandAuthService(authConfig);

        // Inject the mock API client into the service
        var apiClientField = typeof(WristbandAuthService).GetField("_wristbandApiClient", BindingFlags.NonPublic | BindingFlags.Instance);
        apiClientField!.SetValue(service, _mockApiClient.Object);

        // Create a new ConfigResolver with the mocked API client and inject it
        var mockConfigResolver = new ConfigResolver(authConfig, _mockApiClient.Object);
        var configResolverField = typeof(WristbandAuthService).GetField("_configResolver", BindingFlags.NonPublic | BindingFlags.Instance);
        configResolverField!.SetValue(service, mockConfigResolver);

        return service;
    }
}
