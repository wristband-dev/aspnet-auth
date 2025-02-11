## Create Wristband Application:

Some Prod
```
Identifier: --some-identifier--
Environment Type: Production
Domain Name: someprod
Application Vanity Domain: someprod-parent.us.wristband.dev
Application API URL: https://someprod-parent.us.wristband.dev/api

Display Name: Some Prod
Tenant Classifier: Tenant

Login URL: https://{tenant_domain}.mydomain.com/
Logout URLs: 
    https://{tenant_domain}.mydomain.com/
    https://myapp-mytenant-mywristband.us.wristband.dev/login
```

## Create Wristband Application OAuth2 Clients

client01
```
Client ID: --some-identifier--
Client Type: Backend Server

Name: client01

Authorization Callback Url: https://{tenant_domain}.mydomain.com/api/auth/callback
```

clientForManagingUserMetadata
```csharp
Client ID: --some-identifier--
Client Type: Backend Server

Must be assigned a role with:
    Permission Boundary dropdown set to "Application"
    user:manage-restricted-metadata
    user:read
    user:update
```

## Create Wristband Tenants:

One
```
Identifier: --some-identifier--
Tenant Type: Standard
Domain Name: someprodone
Tenant Vanity Domain: someprodone-someprod-parent.us.wristband.dev

Display Name: One
```

Two
```
Identifier: --some-identifier--
Tenant Type: Standard
Domain Name: someprodtwo
Tenant Vanity Domain: someprodtwo-someprod-parent.us.wristband.dev

Display Name: Two
```

Three
```
Identifier: --some-identifier--
Tenant Type: Standard
Domain Name: someprodthree
Tenant Vanity Domain: someprodthree-someprod-parent.us.wristband.dev

Display Name: Three
```
