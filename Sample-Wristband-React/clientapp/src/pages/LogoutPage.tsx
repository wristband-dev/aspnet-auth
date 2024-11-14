import { redirectToLogout } from "../wristbandUtils.ts";
import { useEffect } from "react";

const LogoutPage = () => {

    useEffect(() => {
        const redirect = async () => {
            await redirectToLogout();
        };

        // noinspection JSIgnoredPromiseFromCall
        redirect();
    }, []);

    return <div />;
};

export { LogoutPage };