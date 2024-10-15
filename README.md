## About

This repo contains a pair of simple Hello World examples demonstrating how to use Wristband Auth 
with a C# backend and either React Vite or Blazor WebAssembly frontends. The repo uses Microsoft 
Aspire to launch the C# Asp.Net Core Backend API project, frontend project, and a YARP (Yet Another
Reverse Proxy) to expose the frontend and backend projects as a single endpoint to simplify sharing 
cookies between them.

To keep configuration changes to a minimum when switching from local development to production,
including allowing you to use the "Production" flag on your wristband application when creating 
the application, this sample assumes you are using a free cloudflare tunnel to access your local 
development server via a publicly accessible URL with a valid SSL certificate (provided automatically
by cloudflare). Details on setting up the cloudflare tunnel are found in a separate README in the Wristband project.

The frontend redirects the user's browser to the Wristband Auth server to login. The Wristband Auth 
server then redirects back to the API project which sets a session cookie before returning the user's
browser to the frontend project. The frontend project does not need any secrets or other special
handling, all authorization is handled by the API project.

## Setup

See the [Wristband Project README](./Wristband/README.md) for detailed instructions on adding 
Wristband Auth to your existing Asp.Net Core project and on setting up a Wristband application and tenant
for your project.

To configure this project to run, you will need to create a LoginStateSecret token (explained in the 
Wristband Project README), and you will need to fill in the .NET Secrets and appsettings.json files
for the Apps.Api project (as explained in the Wristband Project README). You will also need to set up
a free CloudFlare tunnel to expose the project running on your local dev machine as a publicly accessible
https url (as explained in the [Cloudflare README](./Wristband/README-Cloudflare-Tunnel.md))

## Run

To debug, using either Visual Studio or Rider, launch the AppHost project using the Aspire launch configuration
(note that if you are new to Aspire, finding the Aspire launch configuration in the dropdown is the only
tricky step of the whole process. The Aspire launch configuration is the one that has the three-nested-triangles
Aspire logo next to it).

To run from the command line without debugging, cd into one of the sample folders (React or Blazor) and
use the following command:

```bash
 dotnet run --project ./AppHost/
```
