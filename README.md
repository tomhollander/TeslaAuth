# TeslaAuth library for C# / .NET Core

Helper library to authenticate to Tesla Owner API.

Includes support for MFA.

This code is heavily based on [Christian P](https://github.com/bassmaster187)'s
work in the [TeslaLogger](https://github.com/bassmaster187/TeslaLogger) tool.
My changes were largely to make it reusable.

Thanks also to [Tim Dorr](https://github.com/timdorr) for his work in documenting the [new API](https://tesla-api.timdorr.com/api-basics/authentication), and [Ramon Smits](https://github.com/ramonsmits) for his contributions to this library.

## Install

The package is available via [NuGet](https://www.nuget.org/) with the package name [TeslaAuth](https://www.nuget.org/packages/TeslaAuth).

```ps1
Install-Package TeslaAuth
```

## Example

Usage example is in the `test.csproj` project, but it's basically just this:

```c#
// When it's time to authenticate:
var authHelper = new TeslaAuthHelper("YourUserAgent/1.0");
var tokens = await authHelper.AuthenticateAsync(username, password, mfaCode);
Console.WriteLine("Access token: " + tokens.AccessToken);
Console.WriteLine("Refresh token: " + tokens.RefreshToken);

// When it's time to refresh:
var newToken = await authHelper.RefreshTokenAsync(tokens.RefreshToken);
```
