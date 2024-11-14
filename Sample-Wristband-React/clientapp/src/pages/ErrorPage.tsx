import { useRouteError } from "react-router-dom";

const ErrorPage = () => {
    const error = useRouteError();
    console.error(error);
    
    return (
        <div id="error-page">
            <h1>Oops!</h1>
            <p>Sorry, an unexpected error has occurred.</p>
            <p>
                <i>{
                    // @ts-expect-error-next-line
                    error.statusText || error.message
                }</i>
            </p>
        </div>
    );
};

export { ErrorPage };