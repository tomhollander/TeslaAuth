# TeslaAuth library for C# / .NET 

Helper library to authenticate to Tesla's API, enabling you to build apps that interact with Tesla's cars and energy products.

Works with both the (soon to be deprecated) Owner API, as well as the new [Fleet API](https://developer.tesla.com/docs/fleet-api)

This code was originally based on [Christian P](https://github.com/bassmaster187)'s
work in the [TeslaLogger](https://github.com/bassmaster187/TeslaLogger) tool.

Thanks also to [Tim Dorr](https://github.com/timdorr) for his work in documenting the [new API](https://tesla-api.timdorr.com/api-basics/authentication), and [Ramon Smits](https://github.com/ramonsmits) for his contributions to this library.

## Install

The package is available via [NuGet](https://www.nuget.org/) with the package name [TeslaAuth](https://www.nuget.org/packages/TeslaAuth).

```ps1
Install-Package TeslaAuth
```

## Supported platforms
The library is compiled using .NET Standard 2.0, and can be used by any flavour of .NET that supports this, including
.NET, .NET Core, .NET Framework, Mono, UWP and Xamarin.

## Sample Apps
This repo includes three samples:

1. A WPF sample that demonstrates a native client authentication with an embedded iframe (only runs on Windows)
2. A console app that launches the system browser to complete authentication - low tech but simple (should work across platforms)
3. An ASP.NET Core app that demonstates web authentication (should work across platforms)

The WPF sample can be used with both the Owner API and the Fleet API. For the latter you need to supply your own Fleet API keys.
You can use any Redirect URL (doesn't even need to be real)

The console and web sample only works with the Fleet API, and you need to supply yout own Fleet API keys. You must use a Redirect
Redirect URL that matches the one configured for your app. For the Console sammple it doesn't matter what this is, but for the web
sample it must the sample website's host, port and path.

## Usage
To authenticate users for the Tesla API, you need to show the Tesla sign in UI in a browser (system or embedded).
Once the user has authenticated, the tokens are posted back to your page or app.

The steps to use this library are:

1. Initialise a `TeslaAuthHelper` instance
2. Call `authHelper.GetLoginUrlForBrowser()` to generate the login URL
3. Show the returned URL in the system browser or your app's integrated browser
4. Monitor the browser until you see a request for a URL containing the your redirect URL, or if you're
building a website, implement the logic directly on the redirect URL
5. Grab the entire URL (it contains a query string) and pass it to `authHelper.GetTokenAfterLoginAsync(...)`
6. This will return a `Tokens` object containing an Access and Refresh token
7. When the token expires, call `authHelper.RefreshTokenAsync(...)` to get a new one without needing a complete login flow.

## Owner API Authentication

The [Tesla Owner API](https://tesla-api.timdorr.com/) is the unofficial API that has been used by third party Tesla apps until 2023.
Anybody can use the API without registration, using a well-known Client ID coded into the TeslaAuth library. While this API is easiest
to use, Tesla have announced it will stop working at some point in the future.

To use the Owner API, you can initialise a `TeslaAuth` instance with the simple constructor (2 optional parameters).

## Fleet API Authentication

The [Fleet API](https://developer.tesla.com/docs/fleet-api) is Tesla's new, officially supported API for third party developers.
In order to use it, you need to first register for an account and then register an app to get a Client ID and other details.
You must also complete additional onboarding steps as described at [developer.tesla.com](https://developer.tesla.com/).

To use the Fleet API, you can initialise a `TeslaAuth` instance passing the `region`, `clientId`, `clientSecret`, `redirectUri` and 
`scope` parameters.
The values you use must match the ones configured in the Tesla developer portal.

## Calling APIs
Once you have obtained a token from TeslaAuth, you can pass it to the Tesla Owner or Fleet API as a Bearer token in the `Authorization`
header. This library does not assist with calling the Tesla APIs; it's only for authentication.

## Contributions
Contributions to this library are welcome. If you want to show your appreciation you can also [support me on Ko-Fi](https://ko-fi.com/tomhollander).