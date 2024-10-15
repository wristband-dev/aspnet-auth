var builder = WebApplication.CreateBuilder(args);

builder.Logging.AddConsole();
builder.AddServiceDefaults();

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    //
    // NOTE: Setting AllowAutoRedirect to true breaks redirects that are required during login process
    //
    //.ConfigureHttpClient((_, handler) =>
    //{
    //    // avoid sending 301 and 307 redirects
    //    handler.AllowAutoRedirect = true;
    //})
    .AddServiceDiscoveryDestinationResolver();

var app = builder.Build();

app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.UseSessionAffinity();
    proxyPipeline.UseLoadBalancing();
    if (false)
    {
        //
        // Diagnostic middleware
        //
        proxyPipeline.Use((context, next) =>
        {
            // Can read data from the request via the context
            Console.WriteLine($"===== {context.Request.Method} {context.Request.Protocol}://{context.Request.Host}/{context.Request.Path}");
            Console.WriteLine($"Body: {context.Request.Body}");
            foreach (var header in context.Request.Headers)
            {
                Console.WriteLine($"Header: `{header.Key}` = `{header.Value}`");
            }

            // The context also stores a ReverseProxyFeature which holds proxy specific data such as the cluster, route and destinations
            var proxyFeature = context.GetReverseProxyFeature();
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(proxyFeature.Route.Config));

            // Important - required to move to the next step in the proxy pipeline
            return next();
        });
    }
});

app.Run();
