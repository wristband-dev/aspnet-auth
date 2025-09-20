<div align="center">
  <a href="https://wristband.dev">
    <picture>
      <img src="https://assets.wristband.dev/images/email_branding_logo_v1.png" alt="Github" width="297" height="64">
    </picture>
  </a>
  <p align="center">
    Migration instruction from version v2.x to version v3.x
  </p>
  <p align="center">
    <b>
      <a href="https://wristband.dev">Website</a> • 
      <a href="https://docs.wristband.dev/">Documentation</a>
    </b>
  </p>
</div>

<br/>

---

<br/>

# Migration instruction from version v2.x to version v3.x

**Legend:**

- (`-`) indicates the older version of the code that needs to be changed
- (`+`) indicates the new and correct version of the code for version 3.x

<br>

## Table of Contents

- [SDK Registration Method Changes](#sdk-registration-method-changes)

<br>

## SDK Registration Method Changes

The deprecated `AddWristbandAuth()` method that accepted `IConfiguration` and `configSectionName` parameters has been removed in version 3.x. You must now use the direct configuration approach.

### Old Method (Removed in v3.x)

```csharp
// Program.cs
builder.Services.AddWristbandAuth(builder.Configuration, "WristbandAuthConfig");
```

<br>

### Expected Methods (Required in v3.x)

The configuration file structure (`appsettings.json`) remains the same, but you must now explicitly bind the configuration values in your `Program.cs` file rather than relying on the deprecated automatic configuration binding method.

**Default Singleton Service**
```csharp
// Program.cs
builder.Services.AddWristbandAuth(options =>
{
    var authConfig = builder.Configuration.GetSection("WristbandAuthConfig");
    options.ClientId = authConfig["ClientId"];
    options.ClientSecret = authConfig["ClientSecret"];
    options.WristbandApplicationVanityDomain = authConfig["WristbandApplicationVanityDomain"];
    // Configure other options as needed...
});
```

**Named Services**
```csharp
// Program.cs
builder.Services.AddWristbandAuth("auth01", options =>
{
    var auth01Config = builder.Configuration.GetSection("WristbandAuthConfig:auth01");
    options.ClientId = auth01Config["ClientId"];
    options.ClientSecret = auth01Config["ClientSecret"];
    options.WristbandApplicationVanityDomain = auth01Config["WristbandApplicationVanityDomain"];
    // Configure other options as needed...
});
 
builder.Services.AddWristbandAuth("auth02", options =>
{
    var auth02Config = builder.Configuration.GetSection("WristbandAuthConfig:auth02");
    options.ClientId = auth02Config["ClientId"];
    options.ClientSecret = auth02Config["ClientSecret"];
    options.WristbandApplicationVanityDomain = auth02Config["WristbandApplicationVanityDomain"];
    // Configure other options as needed...
});
```

<br>

## Questions

Reach out to the Wristband team at <support@wristband.dev> for any questions around migration.

<br/>
