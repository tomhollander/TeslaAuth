// Helper library to authenticate to Tesla Owner API 
// Includes support for MFA.

// This code is heavily based on Christian P (https://github.com/bassmaster187)'s
// work in the TeslaLogger tool (https://github.com/bassmaster187/TeslaLogger).
// My changes were largely to make it reusable.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Newtonsoft.Json.Linq;

namespace TeslaAuth
{
    public class TeslaAuthHelper
    {
        const string TESLA_CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384";
        const string TESLA_CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3";
        static readonly Random Random = new Random();
        readonly ConcurrentDictionary<TeslaAccountRegion, HttpClient> clients = new ConcurrentDictionary<TeslaAccountRegion, HttpClient>();
        readonly string UserAgent;
        readonly LoginInfo loginInfo;
        readonly HttpClient client;
        
        #region Constructor and HttpClient initialisation
        public TeslaAuthHelper(string userAgent, TeslaAccountRegion region = TeslaAccountRegion.Unknown)
        {
            UserAgent = userAgent;
            loginInfo = new LoginInfo
            {
                CodeVerifier = RandomString(86),
                State = RandomString(20)
            };
            client = CreateHttpClient(region);
        }

        HttpClient CreateHttpClient(TeslaAccountRegion region)
        {
            var ch = new HttpClientHandler
            {
                CookieContainer = new CookieContainer(),
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                AllowAutoRedirect = false,
                UseCookies = true
            };

            var client = new HttpClient(ch)
            {
                BaseAddress = new Uri(GetBaseAddressForRegion(region)),
                DefaultRequestHeaders =
                {
                    ConnectionClose = false,
                    Accept = { new MediaTypeWithQualityHeaderValue("application/json") },
                }
            };
            client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);

            return client;
        }
        #endregion

        #region Public API for browser-assisted auth
        public string GetLoginUrlForBrowser()
        {
            var code_challenge_SHA256 = ComputeSHA256Hash(loginInfo.CodeVerifier);
            loginInfo.CodeChallenge = Convert.ToBase64String(Encoding.Default.GetBytes(code_challenge_SHA256));

            var b = new UriBuilder(client.BaseAddress + "/oauth2/v3/authorize") { Port = -1 };

            var q = HttpUtility.ParseQueryString(b.Query);
            q["client_id"] = "ownerapi";
            q["code_challenge"] = loginInfo.CodeChallenge;
            q["code_challenge_method"] = "S256";
            q["redirect_uri"] = "https://auth.tesla.com/void/callback";
            q["response_type"] = "code";
            q["scope"] = "openid email offline_access";
            q["state"] = loginInfo.State;
            b.Query = q.ToString();
            return b.ToString();
        }

        public async Task<Tokens> GetTokenAfterLoginAsync(string redirectUrl, CancellationToken cancellationToken = default)
        {
            // URL is something like https://auth.tesla.com/void/callback?code=b6a6a44dea889eb08cd8afe5adc16353662cc5d82ba0c6044c95b13d6f…"
            var b = new UriBuilder(redirectUrl);
            var q = HttpUtility.ParseQueryString(b.Query);
            var code = q["code"];

            var tokens = await ExchangeCodeForBearerTokenAsync(code, client, cancellationToken);
            var accessAndRefreshTokens = await ExchangeAccessTokenForBearerTokenAsync(tokens.AccessToken, client, cancellationToken);
            return new Tokens
            {
                AccessToken = accessAndRefreshTokens.AccessToken,
                RefreshToken = tokens.RefreshToken,
                CreatedAt = accessAndRefreshTokens.CreatedAt,
                ExpiresIn = accessAndRefreshTokens.ExpiresIn
            };
        }
        #endregion

        #region Public API for headless auth (only works if no CAPTCHA is displayed)
        public async Task<Tokens> AuthenticateAsync(string username, string password, string mfaCode = null, TeslaAccountRegion region = TeslaAccountRegion.Unknown, CancellationToken cancellationToken = default)
        {

            var client = clients.GetOrAdd(region, CreateHttpClient);

            await InitializeLoginAsync(client, cancellationToken);
            var code = await GetAuthorizationCodeAsync(username, password, mfaCode, client, cancellationToken);
            var tokens = await ExchangeCodeForBearerTokenAsync(code, client, cancellationToken);
            var accessAndRefreshTokens = await ExchangeAccessTokenForBearerTokenAsync(tokens.AccessToken, client, cancellationToken);
            return new Tokens
            {
                AccessToken = accessAndRefreshTokens.AccessToken,
                RefreshToken = tokens.RefreshToken,
                CreatedAt = accessAndRefreshTokens.CreatedAt,
                ExpiresIn = accessAndRefreshTokens.ExpiresIn
            };
        }
        #endregion

        #region Public API for token refresh
        public async Task<Tokens> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var body = new JObject
            {
                {"grant_type", "refresh_token"},
                {"client_id", "ownerapi"},
                {"refresh_token", refreshToken},
                {"scope", "openid email offline_access"}
            };

            using var content = new StringContent(body.ToString(), Encoding.UTF8, "application/json");
            using var result = await client.PostAsync("oauth2/v3/token", content, cancellationToken);
            if (!result.IsSuccessStatusCode)
            {
                throw new Exception(string.IsNullOrEmpty(result.ReasonPhrase) ? result.StatusCode.ToString() : result.ReasonPhrase);
            }

            var resultContent = await result.Content.ReadAsStringAsync();
            var response = JObject.Parse(resultContent);
            var accessToken = response["access_token"]!.Value<string>();
            var newTokens = await ExchangeAccessTokenForBearerTokenAsync(accessToken, client, cancellationToken);
            newTokens.RefreshToken = response["refresh_token"]!.Value<string>();
            return newTokens;
        }
        #endregion
        
        #region Authentication helpers
        async Task InitializeLoginAsync(HttpClient client, CancellationToken cancellationToken)
        {
            var loginUrl = GetLoginUrlForBrowser();
            using var response = await client.GetAsync(loginUrl, cancellationToken);
            var resultContent = await response.Content.ReadAsStringAsync();

            var hiddenFields = Regex.Matches(resultContent, "type=\\\"hidden\\\" name=\\\"(.*?)\\\" value=\\\"(.*?)\\\"");
            var formFields = new Dictionary<string, string>();
            foreach (Match match in hiddenFields)
            {
                formFields.Add(match.Groups[1].Value, match.Groups[2].Value);
            }

            loginInfo.FormFields = formFields;

        }

        async Task<string> GetAuthorizationCodeAsync(string username, string password, string mfaCode, HttpClient client, CancellationToken cancellationToken)
        {
            var formFields = loginInfo.FormFields;
            formFields.Add("identity", username);
            formFields.Add("credential", password);

            using var content = new FormUrlEncodedContent(formFields);

            var b = new UriBuilder(client.BaseAddress + "oauth2/v3/authorize") {Port = -1};
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

            using var result = await client.PostAsync(url, content, cancellationToken);
            string resultContent = await result.Content.ReadAsStringAsync();

            if (result.StatusCode != HttpStatusCode.Redirect && !result.IsSuccessStatusCode)
            {
                throw new Exception(string.IsNullOrEmpty(result.ReasonPhrase)
                    ? result.StatusCode.ToString()
                    : result.ReasonPhrase);
            }

            if (result.StatusCode != HttpStatusCode.Redirect)
            {
                if (result.StatusCode == HttpStatusCode.OK && resultContent.Contains("passcode"))
                {
                    if (string.IsNullOrEmpty(mfaCode))
                    {
                        throw new Exception("Multi-factor code required to authenticate");
                    }

                    return await GetAuthorizationCodeWithMfaAsync(mfaCode, loginInfo, client, cancellationToken);
                }
                else
                {
                    throw new Exception("Expected redirect did not occur");
                }
            }

            var location = result.Headers.Location;

            if (location == null)
            {
                throw new Exception("Redirect location not available");
            }

            string code = HttpUtility.ParseQueryString(location.Query).Get("code");
            return code;
        }

        async Task<Tokens> ExchangeCodeForBearerTokenAsync(string code, HttpClient client, CancellationToken cancellationToken)
        {
            var body = new JObject
            {
                {"grant_type", "authorization_code"},
                {"client_id", "ownerapi"},
                {"code", code},
                {"code_verifier", loginInfo.CodeVerifier},
                {"redirect_uri", "https://auth.tesla.com/void/callback"}
            };

            using var content = new StringContent(body.ToString(Newtonsoft.Json.Formatting.None), Encoding.UTF8, "application/json");
            using var result = await client.PostAsync(client.BaseAddress + "oauth2/v3/token", content, cancellationToken);
            if (!result.IsSuccessStatusCode)
            {
                throw new Exception(string.IsNullOrEmpty(result.ReasonPhrase) ? result.StatusCode.ToString() : result.ReasonPhrase);
            }

            string resultContent = await result.Content.ReadAsStringAsync();
            var response = JObject.Parse(resultContent);

            var tokens = new Tokens
            {
                AccessToken = response["access_token"]!.Value<string>(),
                RefreshToken = response["refresh_token"]!.Value<string>()
            };
            return tokens;
        }

        async Task<Tokens> ExchangeAccessTokenForBearerTokenAsync(string accessToken, HttpClient client, CancellationToken cancellationToken)
        {
            var body = new JObject
            {
                {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
                {"client_id", TESLA_CLIENT_ID},
                {"client_secret", TESLA_CLIENT_SECRET}
            };

            using var content = new StringContent(body.ToString(), Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://owner-api.teslamotors.com/oauth/token")
            {
                Content = content,
                Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken) }
            };
            
            using var result = await client.SendAsync(request, cancellationToken);
            
            string resultContent = await result.Content.ReadAsStringAsync();

            var response = JObject.Parse(resultContent);
            var createdAt = DateTimeOffset.FromUnixTimeSeconds(response["created_at"]!.Value<long>());
            var expiresIn = TimeSpan.FromSeconds(response["expires_in"]!.Value<long>());
            var bearerToken = response["access_token"]!.Value<string>();
            var refreshToken = response["refresh_token"]!.Value<string>();

            return new Tokens
            {
                AccessToken = bearerToken,
                RefreshToken = refreshToken,
                CreatedAt = createdAt,
                ExpiresIn = expiresIn
            };
        }

        /// <summary>
        /// Should your Owner API token begin with "cn-" you should POST to auth.tesla.cn Tesla SSO service to have it refresh. Owner API tokens
        /// starting with "qts-" are to be refreshed using auth.tesla.com
        /// </summary>
        /// <param name="region">Which Tesla server is this account created with?</param>
        /// <returns>Address like "https://auth.tesla.com", no trailing slash</returns>
        static string GetBaseAddressForRegion(TeslaAccountRegion region)
        {
            switch (region)
            {
                case TeslaAccountRegion.Unknown:
                case TeslaAccountRegion.USA:
                    return "https://auth.tesla.com";

                case TeslaAccountRegion.China:
                    return "https://auth.tesla.cn";

                default:
                    throw new NotImplementedException("Fell threw switch in GetBaseAddressForRegion for " + region);
            }
        }
        #endregion

        #region MFA helpers
        async Task<string> GetAuthorizationCodeWithMfaAsync(string mfaCode, LoginInfo loginInfo, HttpClient client, CancellationToken cancellationToken)
        {
            var mfaFactorId = await GetMfaFactorIdAsync(mfaCode, loginInfo, client, cancellationToken);
            var code = await GetCodeAfterValidMfaAsync(loginInfo, client, cancellationToken);
            return code;
        }

        async Task<string> GetMfaFactorIdAsync(string mfaCode, LoginInfo loginInfo, HttpClient client, CancellationToken cancellationToken)
        {
            var b = new UriBuilder(client.BaseAddress + "/oauth2/v3/authorize/mfa/factors") {Port = -1};

            var q = HttpUtility.ParseQueryString(b.Query);
            q["transaction_id"] = loginInfo.FormFields["transaction_id"];
            b.Query = q.ToString();
            string url = b.ToString();

            using var  result = await client.GetAsync(url, cancellationToken);
            var resultContent = await result.Content.ReadAsStringAsync();

            var response = JObject.Parse(resultContent);

            for (var i = 0; i < response["data"]!.Count(); i++)
            {
                var mfaFactorId = response["data"]![i]!["id"]!.Value<string>();

                if (await VerifyMfaCodeAsync(mfaCode, loginInfo, mfaFactorId, client, cancellationToken))
                {
                    return mfaFactorId;
                }
            }

            throw new Exception("MFA code not matching on registered devices."); 
        }

        async Task<bool> VerifyMfaCodeAsync(string mfaCode, LoginInfo loginInfo, string factorId, HttpClient client, CancellationToken cancellationToken)
        {
            var body = new JObject
            {
                {"factor_id", factorId},
                {"passcode", mfaCode},
                {"transaction_id", loginInfo.FormFields["transaction_id"]}
            };

            using var content = new StringContent(body.ToString(), Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, "oauth2/v3/authorize/mfa/verify")
            {
                Headers = { Referrer = new Uri("https://auth.tesla.com") },
                Content = content,
            };

            using var result = await client.SendAsync(request, cancellationToken);
            
            string resultContent = await result.Content.ReadAsStringAsync();

            var response = JObject.Parse(resultContent);
            bool valid = response["data"]!["valid"]!.Value<bool>();
            return valid;
        }

        async Task<string> GetCodeAfterValidMfaAsync(LoginInfo loginInfo, HttpClient client, CancellationToken cancellationToken)
        {
            var d = new Dictionary<string, string> {{"transaction_id", loginInfo.FormFields["transaction_id"]}};

            using var content = new FormUrlEncodedContent(d);

            var b = new UriBuilder(client.BaseAddress + "oauth2/v3/authorize") {Port = -1};
            var q = HttpUtility.ParseQueryString(b.Query);
            q["client_id"] = "ownerapi";
            q["code_challenge"] = loginInfo.CodeChallenge;
            q["code_challenge_method"] = "S256";
            q["redirect_uri"] = "https://auth.tesla.com/void/callback";
            q["response_type"] = "code";
            q["scope"] = "openid email offline_access";
            q["state"] = loginInfo.State;
            b.Query = q.ToString();
            var url = b.ToString();

            using var result = await client.PostAsync(url, content, cancellationToken);

            var location = result.Headers.Location;

            if (result.StatusCode == HttpStatusCode.Redirect && location != null)
            {
                return HttpUtility.ParseQueryString(location.Query).Get("code");
            }

            throw new Exception("Unable to get authorization code");
        }
        #endregion

        #region General Utilities
        static string RandomString(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            lock (Random)
            {
                return new string(Enumerable.Repeat(chars, length)
                    .Select(s => s[Random.Next(s.Length)]).ToArray());
            }
        }

        static string ComputeSHA256Hash(string text)
        {
            string hashString;
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(Encoding.Default.GetBytes(text));
                hashString = ToHex(hash, false);
            }

            return hashString;
        }

        static string ToHex(byte[] bytes, bool upperCase)
        {
            StringBuilder result = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                result.Append(bytes[i].ToString(upperCase ? "X2" : "x2"));
            return result.ToString();
        }
        #endregion
    }
}
