import axios from "axios";
import { wrapper } from "axios-cookiejar-support";
import { CookieJar } from "tough-cookie";
import { redirectToLogin } from "./wristbandUtils";

const jar = new CookieJar();

/* CSRF_TOUCHPOINT */
const wristbandApiClient = wrapper(axios.create({
    jar,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    xsrfCookieName: "XSRF-TOKEN",
    xsrfHeaderName: "X-XSRF-TOKEN",
}));

/* WRISTBAND_TOUCHPOINT - AUTHENTICATION */
// Any HTTP 401s should trigger the user to go log in again.  This happens when their
// session cookie has expired and/or the CSRF cookie/header are missing in the request.
// You can optionally catch HTTP 403s as well.

const unauthorizedAccessInterceptor = (error: { response: { status: number } }) => {
    if (error.response && [401].includes(error.response.status)) {
        redirectToLogin("");
    }

    return Promise.reject(error);
};

wristbandApiClient.interceptors.response.use(undefined, unauthorizedAccessInterceptor);

export { wristbandApiClient };
