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

There are two ways of using this library as described below.

## Browser-assisted Example

The most reliable way of using the library is to integrate a WebView into your application and have it show Tesla's login UI. This approach should be resilient
to certain changes on Tesla's side, such as when they randomly decide to include (and later remove) a CAPTCHA on the login page. 
Since Tesla incorporated a CAPTCHA on their login page, it is no longer possible to authenticate using your own UI.

The `Test.WPF` project demonstrates a complete login and refresh flow. The sample only runs on Windows, but the library itself is cross platform (e.g. works on Xamarin).

The steps to use this approach are as follows:

1. Initialise a `TeslaAuthHelper` instance
2. Call `authHelper.GetLoginUrlForBrowser()` to generate the login URL
3. Show the returned URL in your app's integrated browser
4. Monitor the browser until you see a request for a URL containing the string `"void/callback"`
5. Grab the entire URL (it contains a query string) and pass it to `authHelper.GetTokenAfterLoginAsync(...)`
6. This will return a `Tokens` object containing an Access and Refresh token
7. When the token expires, call `authHelper.RefreshTokenAsync(...)` to get a new one without needing a complete login flow.

## Console Example

The other way to use the library is to build your own login UI. The library allows you to capture the user's email address, password and (if configured) multi-factor authentication
code and send these directly to Tesla to obtain tokens. This approach is not reliable due to frequent changes by Tesla, so it is not recommended.

The `Test.Console` project demonstrates a login and refresh flow using this approach. 

The steps to use this approach are as follows:

1. Initialise a `TeslaAuthHelper` instance
2. Call `authHelper.Authenticate(...)` with the user's credentials to obtain the tokens
3. When the token expires, call `authHelper.RefreshTokenAsync(...)` to get a new one without needing a complete login flow.

