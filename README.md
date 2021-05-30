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

Since Tesla incorporated a CAPTCHA on their login page, it is no longer possible to authenticate using your own UI. Instead, you must use an integrated browser to
show the Tesla login page and process the result.

The `Test.WPF` project demonstrates a complete login and refresh flow. The sample only runs on Windows, but the library itself is cross platform (e.g. works on Xamarin).

The steps to use this library are as follows:

1. Initialise a `TeslaAuthHelper` instance
2. Call `authHelper.GetLoginUrlForBrowser()` to generate the login URL
3. Show the returned URL in your app's integrated browser
4. Monitor the browser until you see a request for a URL containing the string `"void/callback"`
5. Grab the entire URL (it contains a query string) and pass it to `authHelper.GetTokenAfterLoginAsync()`
6. This will return a `Tokens` object containing an Access and Refresh token
7. When the token expires, call `authHelper.RefreshTokenAsync()` to get a new one without needing a complete login flow.
