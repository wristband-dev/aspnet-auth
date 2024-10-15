var builder = DistributedApplication.CreateBuilder(args);

//
// Launch the backend API project
//
var api = builder
    .AddProject<Projects.Apps_Api>("api");

//
// Launch the frontend Blazor WebAssembly project.
//
var frontend = builder
    .AddProject<Projects.Apps_Blazor>("frontend")
    .WithReference(api)
    .WithHttpsEndpoint();

//
// Use YARP (Yet Another Reverse Proxy) to expose the API and Frontend
// as a single endpoint so cookies can be easily shared between the two.
//
var yarp = builder
    .AddProject<Projects.Apps_Yarp>("yarp")
    .WithReference(api)
    .WithReference(frontend)
    .WithExternalHttpEndpoints();

builder.Build().Run();
