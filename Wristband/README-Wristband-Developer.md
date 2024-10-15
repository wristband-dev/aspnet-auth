## Create Wristband Application:##

Some Test
```
Identifier: --some-identifier--
Tenancy: Multi-Tenant
Environment Type: Development
Domain Name: sometest
Application Vanity Domain: sometest-parent.us.wristband.dev
Application API URL: https://sometest-parent.us.wristband.dev/api

Display Name: Some Test
Tenant Classifier: Tenant

Login URL: https://{tenant_domain}.mydomain.com/
Logout URLs: https://{tenant_domain}.mydomain.com/
```

## Create Wristband Application OAuth2 Clients##

client01
```
Client ID: --some-identifier--
Client Type: Backend Server

Name: client01

Authorization Callback Url: https://{tenant_domain}.mydomain.com/api/auth/callback
```


## Create Wristband Tenants:##

One
```
Identifier: --some-identifier--
Tenant Type: Standard
Domain Name: sometestone
Tenant Vanity Domain: sometestone-sometest-parent.us.wristband.dev

Display Name: One
```

Two
```
Identifier: --some-identifier--
Tenant Type: Standard
Domain Name: sometesttwo
Tenant Vanity Domain: sometesttwo-sometest-parent.us.wristband.dev

Display Name: Two
```

Three
```
Identifier: --some-identifier--
Tenant Type: Standard
Domain Name: sometestthree
Tenant Vanity Domain: sometestthree-sometest-parent.us.wristband.dev

Display Name: Three
```
