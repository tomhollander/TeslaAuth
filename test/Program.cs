using System;
using System.Threading.Tasks;
using OtpNet;
using TeslaAuth;

class Program
{
    static async Task Main()
    {
        string username = Environment.GetEnvironmentVariable("TESLA_USERNAME") ?? await RL("Username");
        string password = Environment.GetEnvironmentVariable("TESLA_PW") ?? await RL("Password");
        string mfaCode = (mfaCode = Environment.GetEnvironmentVariable("TESLA_KEY")) != null
            ? new OtpNet.Totp(Base32Encoding.ToBytes(mfaCode)).ComputeTotp()
            : await RL("MFA");

        TeslaAccountRegion region = TeslaAccountRegion.Unknown;
        var tokens = await TeslaAuthHelper.AuthenticateAsync(username, password, mfaCode, region);
        Console.WriteLine("Access token: " + tokens.AccessToken);
        Console.WriteLine("Refresh token: " + tokens.RefreshToken);
        Console.WriteLine("Created at: " + tokens.CreatedAt);
        Console.WriteLine("Expires in: " + tokens.ExpiresIn);

        var newToken = await TeslaAuthHelper.RefreshTokenAsync(tokens.RefreshToken, region);
        Console.WriteLine("Refreshed Access token: " + newToken.AccessToken);
        Console.WriteLine("New Refresh token: " + newToken.RefreshToken);
        Console.WriteLine("Refreshed token created at: " + newToken.CreatedAt);
        Console.WriteLine("Refreshed token expires in: " + newToken.ExpiresIn);
    }

    static async Task<string> RL(string label)
    {
        await Console.Out.WriteLineAsync($"{label}: ");
        return Console.ReadLine();
    }
}
