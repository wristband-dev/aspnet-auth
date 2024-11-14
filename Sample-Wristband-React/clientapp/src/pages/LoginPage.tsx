import { redirectToLogin } from "../wristbandUtils.ts";
import { useEffect } from "react";

const LoginPage = () => {
    const loginHint = "/";

    useEffect(() => {
        const redirect = async () => {
            await redirectToLogin(loginHint);
        };
        
        // noinspection JSIgnoredPromiseFromCall
        redirect();
    }, [loginHint]);
    
    return <div />;
};

export { LoginPage };