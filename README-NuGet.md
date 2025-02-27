# Wristband Multi-Tenant Authentication SDK for ASP.NET

Wristband provides enterprise-ready auth that is secure by default, truly multi-tenant, and ungated for small businesses.

- Website: [Wristband Website](https://wristband.dev)
- Documentation: [Wristband Docs](https://docs.wristband.dev/)

For detailed setup instructions and usage guidelines, visit the project's GitHub repository.

- [ASP.NET Auth SDK - GitHub](https://github.com/wristband-dev/aspnet-auth)


## Details

This SDK facilitates seamless interaction with Wristband for user authentication within multi-tenant ASP.NET Core applications. It follows OAuth 2.1 and OpenID standards and is supported for .NET 6+. Key functionalities encompass the following:

- Initiating a login request by redirecting to Wristband.
- Receiving callback requests from Wristband to complete a login request.
- Retrieving all necessary JWT tokens and userinfo to start an application session.
- Logging out a user from the application by revoking refresh tokens and redirecting to Wristband.
- Checking for expired access tokens and refreshing them automatically, if necessary.

You can learn more about how authentication works in Wristband in our documentation:

- [Auth Flows Walkthrough](https://docs.wristband.dev/docs/auth-flows-and-diagrams)
- [Login Workflow In Depth](https://docs.wristband.dev/docs/login-workflow)

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions regarding this SDK.
