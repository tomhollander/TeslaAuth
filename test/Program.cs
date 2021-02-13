using System;
using TeslaAuth;

namespace test
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Username: ");
            string username = Console.ReadLine();
            Console.Write("Password: ");
            string password = Console.ReadLine();
            Console.Write("MFA: ");
            string mfaCode = Console.ReadLine();
            TeslaAccountRegion region = TeslaAccountRegion.Unknown;
            var tokens = TeslaAuthHelper.AuthenticateAsync(username, password, mfaCode, region).Result;
            Console.WriteLine("Access token: " + tokens.AccessToken);
            Console.WriteLine("Refresh token: " + tokens.RefreshToken);
            Console.WriteLine("Created at: " + tokens.CreatedAt);
            Console.WriteLine("Expires in: " + tokens.ExpiresIn);

            var newToken = TeslaAuthHelper.RefreshTokenAsync(tokens.RefreshToken, region).Result;
            Console.WriteLine("Refreshed Access token: " + newToken.AccessToken);
            Console.WriteLine("New Refresh token: " + newToken.RefreshToken);
            Console.WriteLine("Refreshed token created at: " + newToken.CreatedAt);
            Console.WriteLine("Refreshed token expires in: " + newToken.ExpiresIn);
        }
    }
}
