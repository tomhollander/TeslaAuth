using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using OtpNet;
using TeslaAuth;

namespace Test.Console
{
    class Program
    {
        static async Task Main()
        {
            string clientId = Environment.GetEnvironmentVariable("TESLA_CLIENTID") ?? await RL("Client Id");
            string clientSecret = Environment.GetEnvironmentVariable("TESLA_CLIENTSECRET") ?? await RL("Client Secret");
            string redirectUri = Environment.GetEnvironmentVariable("TESLA_REDIRCETURI") ?? await RL("redirectUri");
            string scopes = Scopes.GetScopeString(Scopes.UserData, Scopes.VechicleDeviceData); // Edit if you want...
            var region = TeslaAccountRegion.Unknown;

            var auth = new TeslaAuthHelper("TeslaAuth/1.0", clientId, clientSecret, redirectUri, scopes, region);

            System.Console.WriteLine("Launching browser to authenticate");
            var loginUrl = auth.GetLoginUrlForBrowser();

            OpenBrowser(loginUrl);

            System.Console.WriteLine("After authentication is complete, copy the URL with the code querystring.");
            await RL("Postback URL");

            //string username = Environment.GetEnvironmentVariable("TESLA_USERNAME") ?? await RL("Username");
            //string password = Environment.GetEnvironmentVariable("TESLA_PW") ?? await RL("Password");
            //string mfaCode = (mfaCode = Environment.GetEnvironmentVariable("TESLA_KEY")) != null
            //    ? new Totp(Base32Encoding.ToBytes(mfaCode)).ComputeTotp()
            //    : await RL("MFA");

            //var region = TeslaAccountRegion.Unknown;

            //ServicePointManager.FindServicePoint(new Uri("https://auth.tesla.com")).ConnectionLeaseTimeout = 60 * 1000;
            //ServicePointManager.FindServicePoint(new Uri("https://auth.tesla.com")).ConnectionLimit = 10;
            //ServicePointManager.FindServicePoint(new Uri("https://owner-api.teslamotors.com")).ConnectionLeaseTimeout = 60 * 1000;
            //ServicePointManager.FindServicePoint(new Uri("https://owner-api.teslamotors.com")).ConnectionLimit = 10;

            //var authHelper = new TeslaAuthHelper("TeslaAuthHelperTest/1.0", region);

            //using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

            //var tokens = await authHelper.AuthenticateAsync(username, password, mfaCode, cts.Token);
            //System.Console.WriteLine("Access token: " + tokens.AccessToken);
            //System.Console.WriteLine("Refresh token: " + tokens.RefreshToken);
            //System.Console.WriteLine("Created at: " + tokens.CreatedAt);
            //System.Console.WriteLine("Expires in: " + tokens.ExpiresIn);

            //var newToken = await authHelper.RefreshTokenAsync(tokens.RefreshToken, cts.Token);
            //System.Console.WriteLine("Refreshed Access token: " + newToken.AccessToken);
            //System.Console.WriteLine("New Refresh token: " + newToken.RefreshToken);
            //System.Console.WriteLine("Refreshed token created at: " + newToken.CreatedAt);
            //System.Console.WriteLine("Refreshed token expires in: " + newToken.ExpiresIn);
        }

        static async Task<string> RL(string label)
        {
            await System.Console.Out.WriteLineAsync($"{label}: ");
            return System.Console.ReadLine();
        }

        public static void OpenBrowser(string url)
        {
            try
            {
                Process.Start(url);
            }
            catch
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    url = url.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", url);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", url);
                }
                else
                {
                    throw;
                }
            }
        }
    }
}
