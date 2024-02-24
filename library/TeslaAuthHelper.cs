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
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace TeslaAuth
{
    /// <summary>
    /// TeslaAuthHelper gets the OAuth2 access token and refresh token needed to interact with a Tesla account.
    /// This class is not threadsafe, due to the use of instance state.  It works well for a mobile app used by a single
    /// user at once.  If you are trying to log in with multiple accounts, create a new instance per session.  
    /// Also, Tesla accounts in different countries are stored on different servers (such as China vs. the rest of the world).
    /// You'll need a different instance for each region.
    /// </summary>
    public class TeslaAuthHelper
    {
        // Constants for using the legacy Owner API. Fleet API users supply their own values
        const string TESLA_CLIENT_ID = "ownerapi";
        const string TESLA_CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3";
        const string TESLA_REDIRECT_URI = "https://auth.tesla.com/void/callback";
        const string TESLA_SCOPES = "openid email offline_access";

        static readonly Random Random = new Random();
        readonly string UserAgent;
        readonly LoginInfo loginInfo;
        readonly HttpClient client;
        readonly TeslaAccountRegion region;

        private string clientId;
        private string clientSecret;
        private string redirectUri;
        private string scopes;

        #region Constructor and HttpClient initialisation

        /// <summary>
        /// Constructs an instance of TeslaAuthHelper for use with the Tesla Fleet API. 
        /// </summary>
        /// <param name="region">The API region to use</param>
        /// <param name="clientId">Client ID, as registered in the Tesla developer portal</param>
        /// <param name="clientSecret">Client Secret, as registered in the Tesla developer portal</param>
        /// <param name="redirectUri">URL to redirect to after authentication, as registered in the Tesla developer portal</param>
        /// <param name="scopes">Authorization scopes requested. Use the Scopes helper class to construct</param>
        /// <param name="userAgent">User agent string to use for server-side HTTP requests (can be null)</param>
        public TeslaAuthHelper(TeslaAccountRegion region, string clientId, string clientSecret, string redirectUri, string scopes, string userAgent = null)
        {
            UserAgent = userAgent;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.redirectUri = redirectUri;
            this.scopes = scopes;
            this.region = region;

            loginInfo = new LoginInfo
            {
                CodeVerifier = RandomString(86),
                State = RandomString(20)
            };
            client = CreateHttpClient(region);
        }

        /// <summary>
        /// Constructs an instance of TeslaAuthHelper for use with the Tesla Owner API. 
        /// </summary>
        /// <param name="userAgent">User agent string to use for server-side HTTP requests (can be null)</param>
        /// <param name="region">The API region to use</param>
        public TeslaAuthHelper(string userAgent = null, TeslaAccountRegion region = TeslaAccountRegion.Unknown) : this(region, TESLA_CLIENT_ID, TESLA_CLIENT_SECRET, TESLA_REDIRECT_URI, TESLA_SCOPES, userAgent)
        {
            // Note parameter order is different to the Fleet API constructor for compatibility with older versions. 
            // This constructor will likely be removed if the Owner API becomes unavailable 
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
            if (UserAgent != null)
            {
                client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
            }

            return client;
        }
        #endregion Constructor and HttpClient initialisation

        #region Public API for browser-assisted auth
        public string GetLoginUrlForBrowser()
        {
            byte[] code_challenge_SHA256 = ComputeSHA256HashInBytes(loginInfo.CodeVerifier);
            loginInfo.CodeChallenge = Base64UrlEncode(code_challenge_SHA256);

            var b = new UriBuilder(client.BaseAddress + "oauth2/v3/authorize") { Port = -1 };

            var q = HttpUtility.ParseQueryString(b.Query);
            q["client_id"] = clientId;
            q["code_challenge"] = loginInfo.CodeChallenge;
            q["code_challenge_method"] = "S256";
            q["redirect_uri"] = redirectUri;
            q["response_type"] = "code";
            q["scope"] = scopes;
            q["state"] = loginInfo.State;
            q["nonce"] = RandomString(10);
            //q["locale"] = "en-US";
            b.Query = q.ToString();
            return b.ToString();
        }

        public async Task<Tokens> GetTokenAfterLoginAsync(string redirectUrl, CancellationToken cancellationToken = default)
        {
            // Use the original code verifier from loginInfo - this assumes the same instance of TeslaAuthHelper is in use as was used when making the original request to the Tesla Auth.

            return await GetTokenAfterLoginAsync(redirectUrl, loginInfo.CodeVerifier, cancellationToken);
        }

        public async Task<Tokens> GetTokenAfterLoginAsync(string redirectUrl, string codeVerifier, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(codeVerifier))
            {
                throw new ArgumentException("Must not be null or empty when using this overload", nameof(codeVerifier));
            }

            // URL is something like https://auth.tesla.com/void/callback?code=b6a6a44dea889eb08cd8afe5adc16353662cc5d82ba0c6044c95b13d6f…"
            var b = new UriBuilder(redirectUrl);
            var q = HttpUtility.ParseQueryString(b.Query);
            var error = q["error"];

            if (!String.IsNullOrEmpty(error))
            {
                var errorDescription = q["error_description"];
                throw new InvalidOperationException($"Login failed with error '{error}'\r\n{errorDescription}");
            }

            var code = q["code"];

            // As of March 21 2022, this returns a bearer token.  No need to call ExchangeAccessTokenForBearerToken
            var tokens = await ExchangeCodeForBearerTokenAsync(code, client, codeVerifier, cancellationToken);
            return tokens;

        }
        #endregion Public API for browser-assisted auth

        #region Public API for token refresh
        public async Task<Tokens> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            var body = new JsonObject
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = clientId,
                ["refresh_token"] = refreshToken,
                ["scope"] = scopes
            };

            using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            using var result = await client.PostAsync("oauth2/v3/token", content, cancellationToken);
            var resultContent = await result.Content.ReadAsStringAsync();
            if (!result.IsSuccessStatusCode)
            {
                throw new Exception($"{result.ReasonPhrase} : {resultContent}");
            }

            var response = JsonNode.Parse(resultContent);

            var tokens = new Tokens
            {
                AccessToken = response["access_token"]!.GetValue<string>(),
                RefreshToken = response["refresh_token"]!.GetValue<string>(),
                ExpiresIn = TimeSpan.FromSeconds(response["expires_in"]!.GetValue<long>()),
                TokenType = response["token_type"]!.GetValue<string>(),
                CreatedAt = DateTimeOffset.Now,
            };
            return tokens;

        }
        #endregion Public API for token refresh

        #region Authentication helpers


        async Task<Tokens> ExchangeCodeForBearerTokenAsync(string code, HttpClient client, string codeVerifier, CancellationToken cancellationToken)
        {
            var body = new JsonObject
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["code"] = code,
                ["code_verifier"] = codeVerifier,
                ["redirect_uri"] = redirectUri,
                ["scope"] = scopes,
                ["audience"] = GetAudienceAddressForRegion(region)
            };

            using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            using var result = await client.PostAsync(client.BaseAddress + "oauth2/v3/token", content, cancellationToken);
            string resultContent = await result.Content.ReadAsStringAsync();
            if (!result.IsSuccessStatusCode)
            {
                var failureDetails = resultContent;
                var message = string.IsNullOrEmpty(result.ReasonPhrase) ? result.StatusCode.ToString() : result.ReasonPhrase;
                message += " - " + failureDetails;
                throw new Exception(message);
            }

            var response = JsonNode.Parse(resultContent);

            var tokens = new Tokens
            {
                AccessToken = response["access_token"]!.GetValue<string>(),
                RefreshToken = response["refresh_token"]!.GetValue<string>(),
                ExpiresIn = TimeSpan.FromSeconds(response["expires_in"]!.GetValue<long>()),
                TokenType = response["token_type"]!.GetValue<string>(),
                CreatedAt = DateTimeOffset.Now,
            };
            return tokens;
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
                case TeslaAccountRegion.Europe:
                    return "https://auth.tesla.com";

                case TeslaAccountRegion.China:
                    return "https://auth.tesla.cn";

                default:
                    throw new NotSupportedException("Region not supported: " + region);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="region">The region that hosts the API that the tokens will be used for</param>
        /// <returns>Address like "https://fleet-api.prd.na.vn.cloud.tesla.com", no trailing slash</returns>
        static string GetAudienceAddressForRegion(TeslaAccountRegion region)
        {
            switch (region)
            {
                case TeslaAccountRegion.Unknown:
                case TeslaAccountRegion.USA:
                    return "https://fleet-api.prd.na.vn.cloud.tesla.com";
                case TeslaAccountRegion.Europe:
                    return "https://fleet-api.prd.eu.vn.cloud.tesla.com";
                case TeslaAccountRegion.China:
                    return String.Empty; // We don't know the Fleet API URL for China, and this is ignored for Owner API
                default:
                    throw new NotSupportedException("Region not supported: " + region);

            }
        }
        #endregion Authentication helpers

        #region General Utilities
        public static string RandomString(int length)
        {
            // Technically this should include the characters '-', '.', '_', and '~'.  However let's
            // keep this simpler for now to avoid potential URL encoding issues.
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            lock (Random)
            {
                return new string(Enumerable.Repeat(chars, length)
                    .Select(s => s[Random.Next(s.Length)]).ToArray());
            }
        }

        static byte[] ComputeSHA256HashInBytes(string text)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] textAsBytes = GetBytes(text);  // was Encoding.Default.GetBytes(text) but that depends on the current machine's code page settings.
                var hash = sha256.ComputeHash(textAsBytes);
                return hash;
            }
        }

        public static byte[] GetBytes(String s)
        {
            // This is just a passthrough.  We want to make sure that behavior for characters with a
            // code point value >= 128 is passed through as-is, without depending on your current
            // machine's default ANSI code page or the exact behavior of ASCIIEncoding.  Some people
            // are using UTF-8 but that may vary the length of the code verifier, perhaps inappropriately.
            byte[] bytes = new byte[s.Length];
            for (int i = 0; i < s.Length; i++)
                bytes[i] = (byte)s[i];
            return bytes;
        }

        public static string Base64UrlEncode(byte[] bytes)
        {
            String base64 = Convert.ToBase64String(bytes);
            String encoded = base64
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
            // Note: We are assuming that ToBase64String will never add trailing or leading spaces.
            // We could call String.Trim;  we don't need to.
            return encoded;
        }

        /// <summary>
        /// For testing purposes, create a challenge from a code verifier. 
        /// </summary>
        /// <param name="verifier"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="Exception"></exception>
        public static string Challenge(string verifier)
        {
            if (verifier == null)
                throw new ArgumentNullException(nameof(verifier));

            var bytes = GetBytes(verifier);
            using var hashAlgorithm = SHA256.Create();
            var hash = hashAlgorithm.ComputeHash(bytes);
            var challenge = Base64UrlEncode(hash);

            if (String.IsNullOrEmpty(challenge))
                throw new Exception("Failed to create challenge for verifier");
            return challenge;
        }

        public string GetCurrentCodeVerifier()
        {
            return loginInfo.CodeVerifier;
        }

        public string GetCurrentState()
        {
            return loginInfo.State;
        }

        #endregion General Utilities
    }
}
