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
            string redirectUri = Environment.GetEnvironmentVariable("TESLA_REDIRCETURI") ?? await RL("Redirect URL (from app registration)");
            string scopes = Scopes.BuildScopeString(new[] { Scopes.UserData, Scopes.VehicleDeviceData }); // Edit if you want...
            var region = TeslaAccountRegion.Unknown;

            var auth = new TeslaAuthHelper(region, clientId, clientSecret, redirectUri, scopes);

            System.Console.WriteLine("Launching browser to authenticate");
            System.Console.WriteLine("Once the login process is complete and the browser has redirected with the 'code' query parameter,");
            System.Console.WriteLine("copy and paste the entire URL below.");
            var loginUrl = auth.GetLoginUrlForBrowser();

            OpenBrowser(loginUrl);

            var postbackUrl = await RL("Postback URL");
            var tokens = await auth.GetTokenAfterLoginAsync(postbackUrl);

            System.Console.WriteLine("\r\nAccess token: " + tokens.AccessToken);
            System.Console.WriteLine("Refresh token: " + tokens.RefreshToken);
            System.Console.WriteLine("Token created at: " + tokens.CreatedAt);
            System.Console.WriteLine("Token expires in: " + tokens.ExpiresIn);

            System.Console.WriteLine("\r\nPress ENTER to refresh tokens");
            System.Console.ReadLine();

            var newToken = await auth.RefreshTokenAsync(tokens.RefreshToken);
            System.Console.WriteLine("Refreshed Access token: " + newToken.AccessToken);
            System.Console.WriteLine("New Refresh token: " + newToken.RefreshToken);
            System.Console.WriteLine("Refreshed token created at: " + newToken.CreatedAt);
            System.Console.WriteLine("Refreshed token expires in: " + newToken.ExpiresIn);
        }

        static async Task<string> RL(string label)
        {
            await System.Console.Out.WriteAsync($"{label}: ");
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
