// Helper library to authenticate to Tesla Owner API 
// Includes support for MFA.

// This code is heavily based on Christian P (https://github.com/bassmaster187)'s
// work in the TeslaLogger tool (https://github.com/bassmaster187/TeslaLogger).
// My changes were largely to make it reusable.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using Newtonsoft.Json.Linq;

namespace TeslaAuth
{
    public static class TeslaAuthHelper
    {

        private const string TESLA_CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384";
        private const string TESLA_CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3";
        private static Random random = new Random();
        public static string RandomString(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static string ComputeSHA256Hash(string text)
        {
            string hashString;
            using (var sha256 = SHA256Managed.Create())
            {
                var hash = sha256.ComputeHash(Encoding.Default.GetBytes(text));
                hashString = ToHex(hash, false);
            }

            return hashString;
        }

        private static string ToHex(byte[] bytes, bool upperCase)
        {
            StringBuilder result = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                result.Append(bytes[i].ToString(upperCase ? "X2" : "x2"));
            return result.ToString();
        }


        public static Tokens Authenticate(string username, string password, string mfaCode = null)
        {
            var loginInfo = InitializeLogin();
            var code = GetAuthorizationCode(username, password, mfaCode, loginInfo);
            var tokens = ExchangeCodeForBearerToken(code, loginInfo);
            var accessToken = ExchangeAccessTokenForBearerToken(tokens.AccessToken);
            return new Tokens {
                AccessToken = accessToken,
                RefreshToken = tokens.RefreshToken
            };
        }


        private static LoginInfo InitializeLogin() 
        {
            var result = new LoginInfo();

            result.CodeVerifier = RandomString(86);

            var code_challenge_SHA256 = ComputeSHA256Hash(result.CodeVerifier);
            result.CodeChallenge = Convert.ToBase64String(Encoding.Default.GetBytes(code_challenge_SHA256)); 

            result.State = RandomString(20);
                
            using (HttpClient client = new HttpClient())
            {
                Dictionary<string, string> values = new Dictionary<string, string>
                {
                    { "client_id", "ownerapi" },
                    { "code_challenge", result.CodeChallenge },
                    { "code_challenge_method", "S256" },
                    { "redirect_uri", "https://auth.tesla.com/void/callback" },
                    { "response_type", "code" },
                    { "scope", "openid email offline_access" },
                    { "state", result.State }
                };

        
                UriBuilder b = new UriBuilder("https://auth.tesla.com/oauth2/v3/authorize");
                b.Port = -1;
                var q = HttpUtility.ParseQueryString(b.Query);
                foreach(var v in values)
                {
                    q[v.Key] = v.Value;
                }
                b.Query = q.ToString();
                string url = b.ToString();

                    
                HttpResponseMessage response = client.GetAsync(url).Result;
                var resultContent = response.Content.ReadAsStringAsync().Result;

                var hiddenFields = Regex.Matches(resultContent, "type=\\\"hidden\\\" name=\\\"(.*?)\\\" value=\\\"(.*?)\\\"");
                var formFields = new Dictionary<string, string>();
                foreach (Match match in hiddenFields)
                {
                    formFields.Add(match.Groups[1].Value, match.Groups[2].Value);
                }

                IEnumerable<string> cookies = response.Headers.SingleOrDefault(header => header.Key == "Set-Cookie").Value;
                var cookie = cookies.ToList()[0];
                cookie = cookie.Substring(0, cookie.IndexOf(" "));
                cookie = cookie.Trim();

                result.Cookie = cookie;
                result.FormFields = formFields;
                
                return result;
  
            }

            
        }

        private static string GetAuthorizationCode(string username, string password, string mfaCode, LoginInfo loginInfo)
        {
            var formFields = loginInfo.FormFields;
            formFields.Add("identity", username);
            formFields.Add("credential", password);

            string code = "";

            using (HttpClientHandler ch = new HttpClientHandler())
            {
                ch.AllowAutoRedirect = false;
                ch.UseCookies = false;
                using (HttpClient client = new HttpClient(ch))
                {
                    // client.Timeout = TimeSpan.FromSeconds(10);
                    client.BaseAddress = new Uri("https://auth.tesla.com");
                    client.DefaultRequestHeaders.Add("Cookie", loginInfo.Cookie);
                    DateTime start = DateTime.UtcNow;

                    using (FormUrlEncodedContent content = new FormUrlEncodedContent(formFields))
                    {
                        UriBuilder b = new UriBuilder("https://auth.tesla.com/oauth2/v3/authorize");
                        b.Port = -1;
                        var q = HttpUtility.ParseQueryString(b.Query);
                        q["client_id"] = "ownerapi";
                        q["code_challenge"] = loginInfo.CodeChallenge;
                        q["code_challenge_method"] = "S256";
                        q["redirect_uri"] = "https://auth.tesla.com/void/callback";
                        q["response_type"] = "code";
                        q["scope"] = "openid email offline_access";
                        q["state"] = loginInfo.State;
                        b.Query = q.ToString();
                        string url = b.ToString();

                        //var temp = content.ReadAsStringAsync().Result;

                        HttpResponseMessage result = client.PostAsync(url, content).Result;
                        string resultContent = result.Content.ReadAsStringAsync().Result;

                        if (!result.IsSuccessStatusCode)
                        {
                            throw new Exception(result.ReasonPhrase);
                        }
                        Uri location = result.Headers.Location;

                        
                        if (result.StatusCode != HttpStatusCode.Redirect)
                        {
                            if (result.StatusCode == HttpStatusCode.OK && resultContent.Contains("passcode"))
                            {
                                if (String.IsNullOrEmpty(mfaCode)) 
                                {
                                    throw new Exception("Multi-factor code required to authenticate");
                                }
                                return GetAuthorizationCodeWithMfa(mfaCode, loginInfo);

    
                            }
                            else
                            {
                                throw new Exception("Expected redirect did not occur");
                            }
                        }

                        if (location == null)
                        {
                            throw new Exception("Redirect locaiton not available");
                        }

                        code = HttpUtility.ParseQueryString(location.Query).Get("code");
                        return code;
                        
                    }
                }
            }
            throw new Exception("Authentication process failed");
        }

        private static Tokens ExchangeCodeForBearerToken(string code, LoginInfo loginInfo)
        {
            var body = new JObject();
            body.Add("grant_type", "authorization_code");
            body.Add("client_id", "ownerapi");
            body.Add("code", code);
            body.Add("code_verifier", loginInfo.CodeVerifier);
            body.Add("redirect_uri", "https://auth.tesla.com/void/callback");

            using (HttpClient client = new HttpClient())
            {
                client.BaseAddress = new Uri("https://auth.tesla.com");

                using (var content = new StringContent(body.ToString(), System.Text.Encoding.UTF8, "application/json"))
                {
                    HttpResponseMessage result = client.PostAsync("https://auth.tesla.com/oauth2/v3/token", content).Result;
                    string resultContent = result.Content.ReadAsStringAsync().Result;

                    JObject response = JObject.Parse(resultContent);
                    
                    var tokens = new Tokens()
                    {
                        AccessToken = response["access_token"].Value<string>(),
                        RefreshToken = response["refresh_token"].Value<string>()
                    };
                    return tokens;

                }
            }  
        }

        private static string ExchangeAccessTokenForBearerToken(string accessToken)
        {   
            var body = new JObject();
            body.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            body.Add("client_id", TESLA_CLIENT_ID);
            body.Add("client_secret", TESLA_CLIENT_SECRET);

            using (HttpClient client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(5);
                client.DefaultRequestHeaders.Add("Authorization", "Bearer " + accessToken);

                using (var content = new StringContent(body.ToString(), System.Text.Encoding.UTF8, "application/json"))
                {
                    HttpResponseMessage result = client.PostAsync("https://owner-api.teslamotors.com/oauth/token", content).Result;
                    string resultContent = result.Content.ReadAsStringAsync().Result;

                    JObject response = JObject.Parse(resultContent);
                    
                    return response["access_token"].Value<String>();
                }
            }
   
        }

        public static string RefreshToken(string refreshToken) 
        {
            var body = new JObject();
            body.Add("grant_type", "refresh_token");
            body.Add("client_id", "ownerapi");
            body.Add("refresh_token", refreshToken);
            body.Add("scope", "openid email offline_access");

            using (HttpClient client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromSeconds(5);

                using (var content = new StringContent(body.ToString(), System.Text.Encoding.UTF8, "application/json"))
                {
                    HttpResponseMessage result = client.PostAsync("https://auth.tesla.com/oauth2/v3/token", content).Result;
                    string resultContent = result.Content.ReadAsStringAsync().Result;

                    JObject response = JObject.Parse(resultContent);
                    
                    string accessToken = response["access_token"].Value<String>();
                    return ExchangeAccessTokenForBearerToken(accessToken);
                }
            }
        }

        private static string GetAuthorizationCodeWithMfa(string mfaCode, LoginInfo loginInfo)
        {
            string mfaFactorId = GetMfaFactorId(loginInfo);
            VerifyMfaCode(mfaCode, loginInfo, mfaFactorId);
            var code = GetCodeAfterValidMfa(loginInfo);
            return code;
        }

        private static string GetMfaFactorId(LoginInfo loginInfo)
        {
            string resultContent;
            using (HttpClientHandler ch = new HttpClientHandler())
            {
                ch.UseCookies = false;
                using (HttpClient client = new HttpClient(ch))
                {
                    client.DefaultRequestHeaders.Add("Cookie", loginInfo.Cookie);
                    
                    UriBuilder b = new UriBuilder("https://auth.tesla.com/oauth2/v3/authorize/mfa/factors");
                    b.Port = -1;

                    var q = HttpUtility.ParseQueryString(b.Query);
                    q.Add("transaction_id", loginInfo.FormFields["transaction_id"]);
                    b.Query = q.ToString();
                    string url = b.ToString();

                    HttpResponseMessage result = client.GetAsync(url).Result;
                    resultContent = result.Content.ReadAsStringAsync().Result;

                    var response = JObject.Parse(resultContent);
  
                    return response["data"][0]["id"].Value<string>();

                }
            }
        }

        private static void VerifyMfaCode(string mfaCode, LoginInfo loginInfo, string factorId)
        {
            using (HttpClientHandler ch = new HttpClientHandler())
            {
                ch.AllowAutoRedirect = false;
                ch.UseCookies = false;
                using (HttpClient client = new HttpClient(ch))
                {
                    client.BaseAddress = new Uri("https://auth.tesla.com");
                    client.DefaultRequestHeaders.Add("Cookie", loginInfo.Cookie);

                    var body = new JObject();
                    body.Add("factor_id", factorId);
                    body.Add("passcode", mfaCode);
                    body.Add("transaction_id", loginInfo.FormFields["transaction_id"]);


                    using (var content = new StringContent(body.ToString(), System.Text.Encoding.UTF8, "application/json"))
                    {
                        HttpResponseMessage result = client.PostAsync("https://auth.tesla.com/oauth2/v3/authorize/mfa/verify", content).Result;
                        string resultContent = result.Content.ReadAsStringAsync().Result;

                        var response = JObject.Parse(resultContent);
                        bool valid = response["data"]["valid"].Value<bool>();
                        if (!valid) {
                            throw new Exception("MFA code invalid");
                        }
                 
                    }
                }
            }


        }

        private static string GetCodeAfterValidMfa(LoginInfo loginInfo)
        {
            using (HttpClientHandler ch = new HttpClientHandler())
            {
                ch.AllowAutoRedirect = false;
                ch.UseCookies = false;
                using (HttpClient client = new HttpClient(ch))
                {
                    // client.Timeout = TimeSpan.FromSeconds(10);
                    client.BaseAddress = new Uri("https://auth.tesla.com");
                    client.DefaultRequestHeaders.Add("Cookie", loginInfo.Cookie);

                    Dictionary<string, string> d = new Dictionary<string, string>();
                    d.Add("transaction_id", loginInfo.FormFields["transaction_id"]);

                    using (FormUrlEncodedContent content = new FormUrlEncodedContent(d))
                    {
                        UriBuilder b = new UriBuilder("https://auth.tesla.com/oauth2/v3/authorize");
                        b.Port = -1;
                        var q = HttpUtility.ParseQueryString(b.Query);
                        q.Add("client_id", "ownerapi");
                        q.Add("code_challenge", loginInfo.CodeChallenge);
                        q.Add("code_challenge_method", "S256");
                        q.Add("redirect_uri", "https://auth.tesla.com/void/callback");
                        q.Add("response_type", "code");
                        q.Add("scope", "openid email offline_access");
                        q.Add("state", loginInfo.State);
                        b.Query = q.ToString();
                        string url = b.ToString();

                        var temp = content.ReadAsStringAsync().Result;

                        HttpResponseMessage result = client.PostAsync(url, content).Result;
                        string resultContent = result.Content.ReadAsStringAsync().Result;

                        Uri location = result.Headers.Location;

                        if (result.StatusCode == HttpStatusCode.Redirect && location != null)
                        {
                            return HttpUtility.ParseQueryString(location.Query).Get("code");
                        }
                        throw new Exception("Unable to get authorization code");
                    }
                }
            }

        }

    }
}

