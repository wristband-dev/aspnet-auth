import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

import { Router } from "./Router";
import { WristbandAuthProvider } from "./WristbandAuthProvider";
import { WristbandTenantProvider } from "./WristbandTenantProvider";

import "./App.css";
import styles from "./App.module.css";

import otherLogo from "./assets/other-logo.svg";

const disableAuthForTesting = false;

const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            refetchOnWindowFocus: false,
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            retry: (count, args: any) => {
                if (["401", "403"].includes(args.response.status)) {
                    return false;
                }
                return count < 3;
            },
            staleTime: 30000,
        },
    },
});

function App() {
    return (
        <QueryClientProvider client={queryClient}>
            <WristbandAuthProvider
                disableAuthForTesting={disableAuthForTesting}
                securing={
                    <div className={styles.fullScreen}>
                        <p className={styles.centeredText}>Securing...</p>
                    </div>
                }
            >
                <WristbandTenantProvider tenants={{ default: { name: "Other", logo: otherLogo }}}>
                    <Router />
                </WristbandTenantProvider>
            </WristbandAuthProvider>
            { false && <ReactQueryDevtools initialIsOpen={false} position="bottom-right" />}
        </QueryClientProvider>
    )
}

export default App
