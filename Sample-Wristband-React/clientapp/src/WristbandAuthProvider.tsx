import { createContext, PropsWithChildren, ReactNode, useContext, useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { getAuthState, redirectToLogin, redirectToLogout } from "./wristbandUtils";

export type IsAuthenticatedOptions = "authenticated" | "not-authenticated" | "unknown";

interface IWristbandAuthContext {
    isAuthenticated: IsAuthenticatedOptions;
}

const WristbandAuthContext = createContext<IWristbandAuthContext>({ isAuthenticated: "unknown" });

interface IOwnProps {
    disableAuthForTesting: boolean;
    securing: ReactNode;
}

function WristbandAuthProvider({ children, disableAuthForTesting, securing }: PropsWithChildren<IOwnProps>) {
    const queryClient = useQueryClient();
    const [isAuthenticated, setIsAuthenticated] = useState<IsAuthenticatedOptions>("unknown");
  
    // Bootstrap the application with the authenticated user's session data.
    useEffect(() => {    
        const fetchSession = async () => {
            if (disableAuthForTesting) {
                setIsAuthenticated("authenticated");
                return;
            }

            try {
                /* WRISTBAND_TOUCHPOINT - AUTHENTICATION */
                /* CSRF_TOUCHPOINT */
                // The auth state API will let React know if the user has a previously authenticated session. If so,
                // it will establish a the CSRF cookie and then move on to initializing session data.
                const serverAuthenticated = await getAuthState();
                if (!serverAuthenticated) {
                    setIsAuthenticated("not-authenticated");
                    const params = new URLSearchParams(window.location.search);
                    const loginHint = params.get("login_hint") ?? "";
                    await redirectToLogin(loginHint);
                } else {
                    /* WRISTBAND_TOUCHPOINT - AUTHENTICATION */

                    //
                    // Application-specific session data can be loaded here
                    //
                    // // We make one call to load all session data to reduce network requests, and then split up the
                    // // results into separate cache keys since each key could read/write indepenently of each other.
                    // const sessionData = await getInitialSessionData();
                    // const { assignedRole, company, configs, user } = sessionData;
                    // queryClient.setQueryData(["session-user"], user);
                    // queryClient.setQueryData(["session-role"], assignedRole);
                    // queryClient.setQueryData(["session-company"], company);
                    // queryClient.setQueryData(["session-configs"], configs);

                    setIsAuthenticated("authenticated");
                }
            } catch (error) {
                console.log(error);
                setIsAuthenticated("not-authenticated");
                await redirectToLogout();
            }
        };
  
        fetchSession();
    }, [disableAuthForTesting, queryClient]);
  
    return (
        <WristbandAuthContext.Provider value={{ isAuthenticated }}>
            {isAuthenticated === "unknown" || isAuthenticated === "not-authenticated" ?
                securing : children}
        </WristbandAuthContext.Provider>
    );
}

function useWristbandAuth() {
    const context = useContext(WristbandAuthContext);
    if (context === undefined) {
        throw new Error("useWristbandAuth must be used within a WristbandAuthProvider");
    }
    return context;
}

/* WRISTBAND_TOUCHPOINT - AUTHENTICATION */
// React context responsbile for establishing that the user is authenticated and getting session data.
// "AuthProvider" should wrap your App component to enable access to the "useAuth" hook everywhere.
// That hook can then be used to protect App routes.

// eslint-disable-next-line react-refresh/only-export-components
export { WristbandAuthProvider, useWristbandAuth };
