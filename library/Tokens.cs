using System;

namespace TeslaAuth
{

    public class Tokens
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTimeOffset CreatedAt { get; set; }
        public TimeSpan ExpiresIn { get; set; }
        public string TokenType { get; set; }
    }
}