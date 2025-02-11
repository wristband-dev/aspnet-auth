## Running Test Commands

The following commands are meant to be invoked from this project's root dir as opposed to within the `tests` directory.

### Run Tests for All Files

```dotnetcli
dotnet test --framework net8.0
```

### Run All Tests in a Single Test File

```dotnetcli
// Replace with desired file name you want to test
dotnet test --framework net8.0 --filter FullyQualifiedName~Wristband.AspNet.Auth.Tests.LogoutConfigTests
```

### Run a Single Test from a Single Test File

```dotnetcli
// Replace with desired file name and method name you want to test
dotnet test --framework net8.0 --filter FullyQualifiedName~Wristband.AspNet.Auth.Tests.LogoutConfigTests.Constructor_WithValidValues_SetsProperties
```

### Run Tests and Output Test Results

```dotnetcli
dotnet test --framework net8.0 --collect:"XPlat Code Coverage"
```

### Generate Code Coverage Report After Test Run

```dotnetcli
dotnet tool run reportgenerator -reports:"tests/TestResults/**/*.cobertura.xml" -targetdir:"tests/CoverageReport"
```

### View Coverage Report

```dotnetcli
// macOS/Linux
open tests/CoverageReport/index.htm
// Windows
start tests/CoverageReport/index.htm
```
