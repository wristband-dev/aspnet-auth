using Microsoft.AspNetCore.Components.Authorization;
using System.Net.Http.Json;
using System.Security.Claims;

namespace Apps.Blazor;

using Microsoft.AspNetCore.Components;

public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private const string LocalStorageKey = "currentUser";
    private HttpClient mHttpClient { get; set; }
    private NavigationManager mNavigationManager { get; set; }
    private readonly CustomAuthenticationLocalStorageService mLocalStorageService;

    public CustomAuthenticationStateProvider(
        HttpClient httpClient,
        NavigationManager navigationManager,
        CustomAuthenticationLocalStorageService localStorageService)
    {
        mHttpClient = httpClient;
        mNavigationManager = navigationManager;
        mLocalStorageService = localStorageService;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var user = await GetCurrentUserAsync();

        if (user == null)
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        var claims = new Claim[] {
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.Email, user.Email),
        };

        var authenticationState = new AuthenticationState(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    claims, authenticationType: nameof(CustomAuthenticationStateProvider))));

        return authenticationState;
    }

    private async Task SetCurrentUserAsync(CustomAuthenticationUser user)
    {
        await mLocalStorageService.SetItem(LocalStorageKey, user);

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task<CustomAuthenticationUser?> GetCurrentUserAsync()
    {
        try
        {
            var storedUser =
                await mLocalStorageService.GetItemAsync<CustomAuthenticationUser>(LocalStorageKey);
            if (storedUser != null)
            {
                return storedUser;
            }

            var baseUri = mNavigationManager.BaseUri;
            var authStateUrl = $"{baseUri}api/auth/auth-state";
            var response = await mHttpClient.GetAsync(authStateUrl);
            if (response.IsSuccessStatusCode)
            {
                var authStateResponse =
                    await response.Content.ReadFromJsonAsync<AuthStateResponse>();
                if (authStateResponse != null)
                {
                    var user = CreateUserFromAuthStateResponse(authStateResponse);
                    if (user != null)
                    {
                        await SetCurrentUserAsync(user);
                        return user;
                    }
                }
            }
            else
            {
                Console.WriteLine($"Failed to fetch login URL: {response.StatusCode}");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Failed to fetch login URL: {e}");
        }

        return null;
    }

    public async Task RemoveCurrentUserAsync()
    {
        await mLocalStorageService.RemoveItemAsync(LocalStorageKey);
    }

    private static CustomAuthenticationUser? CreateUserFromAuthStateResponse(AuthStateResponse authStateResponse)
    {
        if (!authStateResponse.IsAuthenticated)
        {
            return null;
        }

        return new CustomAuthenticationUser(authStateResponse.Name, authStateResponse.Email);
    }

    public class AuthStateResponse
    {
        public bool IsAuthenticated { get; set; }
        public string Name { get; set; } = "";
        public string Email { get; set; } = "";
    }
}
