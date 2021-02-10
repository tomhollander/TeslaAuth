# TeslaAuth library for C# / .NET Core

Helper library to authenticate to Tesla Owner API.

Includes support for MFA.

This code is heavily based on [Christian P](https://github.com/bassmaster187)'s
work in the [TeslaLogger](https://github.com/bassmaster187/TeslaLogger) tool.
My changes were largely to make it reusable.

Thanks also to [Tim Dorr](https://github.com/timdorr) for his work in documenting the [new API](https://tesla-api.timdorr.com/api-basics/authentication).

Usage example is in the `test.csproj` project, but it's basically just this:

```
// When it's time to authenticate:
var tokens = TeslaAuthHelper.Authenticate(username, password, mfaCode);
Console.WriteLine("Access token: " + tokens.AccessToken);
Console.WriteLine("Refresh token: " + tokens.RefreshToken);

// When it's time to refresh:
var newToken = TeslaAuthHelper.RefreshToken(tokens.RefreshToken);
```