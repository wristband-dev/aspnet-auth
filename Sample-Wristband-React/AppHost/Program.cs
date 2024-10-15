var builder = DistributedApplication.CreateBuilder(args);

//
// Launch the backend API project
//
var api = builder
    .AddProject<Projects.Apps_Api>("api");

//
// Launch the frontend React Vite project (the React code is
// visible the in repo but not shown in Visual Studio or Rider,
// which focus on C# projects).
//
var frontend = builder
    .AddNpmApp("frontend", "../clientapp", "start")
    .WithReference(api)
    .WithHttpEndpoint(env: "PORT")
    .PublishAsDockerFile();

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
