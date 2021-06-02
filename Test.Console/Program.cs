using System;
using System.Net;
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
            string username = Environment.GetEnvironmentVariable("TESLA_USERNAME") ?? await RL("Username");
            string password = Environment.GetEnvironmentVariable("TESLA_PW") ?? await RL("Password");
            string mfaCode = (mfaCode = Environment.GetEnvironmentVariable("TESLA_KEY")) != null
                ? new Totp(Base32Encoding.ToBytes(mfaCode)).ComputeTotp()
                : await RL("MFA");

            var region = TeslaAccountRegion.Unknown;

            ServicePointManager.FindServicePoint(new Uri("https://auth.tesla.com")).ConnectionLeaseTimeout = 60 * 1000;
            ServicePointManager.FindServicePoint(new Uri("https://auth.tesla.com")).ConnectionLimit = 10;
            ServicePointManager.FindServicePoint(new Uri("https://owner-api.teslamotors.com")).ConnectionLeaseTimeout = 60 * 1000;
            ServicePointManager.FindServicePoint(new Uri("https://owner-api.teslamotors.com")).ConnectionLimit = 10;

            var authHelper = new TeslaAuthHelper("TeslaAuthHelperTest/1.0");

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

            var tokens = await authHelper.AuthenticateAsync(username, password, mfaCode, region, cts.Token);
            System.Console.WriteLine("Access token: " + tokens.AccessToken);
            System.Console.WriteLine("Refresh token: " + tokens.RefreshToken);
            System.Console.WriteLine("Created at: " + tokens.CreatedAt);
            System.Console.WriteLine("Expires in: " + tokens.ExpiresIn);

            var newToken = await authHelper.RefreshTokenAsync(tokens.RefreshToken, cts.Token);
            System.Console.WriteLine("Refreshed Access token: " + newToken.AccessToken);
            System.Console.WriteLine("New Refresh token: " + newToken.RefreshToken);
            System.Console.WriteLine("Refreshed token created at: " + newToken.CreatedAt);
            System.Console.WriteLine("Refreshed token expires in: " + newToken.ExpiresIn);
        }

        static async Task<string> RL(string label)
        {
            await System.Console.Out.WriteLineAsync($"{label}: ");
            return System.Console.ReadLine();
        }
    }
}
