import { wristbandApiClient } from "./wristbandApiClient";

export async function redirectToLogout() {
    //
    // Request the redirect url, then perform the redirect as separate stesp,
    // so the response from the api server can update the session and cookies
    //
    const response = await wristbandApiClient.get("/api/logout");
    const wristbandLogoutUrl = response.data.wristbandLogoutUrl;
    window.location = wristbandLogoutUrl as unknown as Location;
}
  
export async function redirectToLogin(loginHint: string) {
    //
    // Request the redirect url, then perform the redirect as separate stesp,
    // so the response from the api server can update the session and cookies
    //
    const query = new URLSearchParams({ 
        return_url: encodeURI(window.location.href),
        login_hint: loginHint,
     }).toString();
    const response = await wristbandApiClient.get(`/api/login?${query}`);
    const wristbandLoginUrl = await response.data.wristbandLoginUrl;
    window.location = wristbandLoginUrl as unknown as Location;
}
  
export function isOwnerRole(roleName: string) {
    // Should match the Role "name" field, i.e. "app:invotasticb2b:owner"
    return /^app:.*:owner$/.test(roleName);
}

export const getAuthState = async function () {
    const response = await wristbandApiClient.get("/api/auth/auth-state");
    return response.data.isAuthenticated;
};
  