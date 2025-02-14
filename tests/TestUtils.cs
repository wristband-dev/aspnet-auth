using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Wristband.AspNet.Auth.Tests;

public static class TestUtils
{
    public static HttpContext setupHttpContext(
        string host,
        string? queryString = null,
        Dictionary<string, string>? requestCookies = null)
    {
        DefaultHttpContext httpContext = new DefaultHttpContext();

        httpContext.Request.Host = new HostString(host);

        if (!string.IsNullOrEmpty(queryString))
        {
            httpContext.Request.QueryString = new QueryString($"?{queryString}");
        }

        if (requestCookies != null)
        {
            var cookieFeature = new RequestCookiesFeature(new TestRequestCookieCollection(requestCookies));
            httpContext.Features.Set<IRequestCookiesFeature>(cookieFeature);

        }

        return httpContext;
    }
}
