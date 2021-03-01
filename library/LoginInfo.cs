using System.Collections.Generic;

namespace TeslaAuth 
{
    internal class LoginInfo
    {
        public string CodeVerifier { get; set;}
        public string CodeChallenge { get; set;}
        public string State { get; set;}
        public Dictionary<string, string> FormFields { get; set;}
    }
}
