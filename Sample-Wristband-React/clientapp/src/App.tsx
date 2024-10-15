import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

import "./App.css";
import styles from "./App.module.css";

import { WristbandAuthProvider } from "./WristbandAuthProvider";
import { WristbandTenantProvider } from "./WristbandTenantProvider";
import HomePage from "./HomePage";

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
                <WristbandTenantProvider
                    tenants={{
                        default: { name: "Other", logo: otherLogo },
                    }}
                >
                    <HomePage />
                </WristbandTenantProvider>
            </WristbandAuthProvider>
            { false && <ReactQueryDevtools initialIsOpen={false} position="bottom-right" />}
        </QueryClientProvider>
    )
}

export default App
