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
            var tokens = TeslaAuthHelper.Authenticate(username, password, mfaCode);
            Console.WriteLine("Access token: " + tokens.AccessToken);
            Console.WriteLine("Refresh token: " + tokens.RefreshToken);

            var newToken = TeslaAuthHelper.RefreshToken(tokens.RefreshToken);
            Console.WriteLine("Refreshed Access token: " + newToken);
        }
    }
}
