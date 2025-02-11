## Running Test Commands

Tests must be run from within the `tests` directory.

### Run Tests for All Files

```dotnetcli
dotnet test --framework net8.0
```

### Run All Tests in a Single Test File

```dotnetcli
// Replace with desired file name you want to test
dotnet test --framework net8.0 --filter FullyQualifiedName~Wristband.Tests.LogoutConfigTests
```

### Run a Single Test from a Single Test File

```dotnetcli
// Replace with desired file name and method name you want to test
dotnet test --framework net8.0 --filter FullyQualifiedName~Wristband.Tests.LogoutConfigTests.Constructor_WithValidValues_SetsProperties
```

### Run Tests and Output Test Results

```dotnetcli
dotnet test --framework net8.0 --collect:"XPlat Code Coverage"
```

### Generate Code Coverage Report After Test Run

```dotnetcli
dotnet tool run reportgenerator -reports:"TestResults/**/*.cobertura.xml" -targetdir:CoverageReport
```

### View Coverage Report

```dotnetcli
// macOS/Linux
open CoverageReport/index.htm
// Windows
start CoverageReport/index.htm
```
