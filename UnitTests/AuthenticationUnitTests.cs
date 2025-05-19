using System.Diagnostics;
using System.Web;
using TeslaAuth;

namespace UnitTests
{
    [TestClass]
    public class AuthenticationUnitTests
    {
        [TestMethod]
        public void CodeVerifierTests()
        {
            // These are some simple test cases for code verifiers, inspired by this article about
            // RFC 7636, "Proof Key for Code Exchange", which includes these test cases:
            // https://www.mickf.net/tech/oauth-pkce-swift-secure-code-verifiers-and-code-challenges/

            byte[] aZTestBytes = new byte[] { 3, 236, 255, 224, 193 };
            Assert.AreEqual("A-z_4ME", TeslaAuthHelper.Base64UrlEncode(aZTestBytes));


            byte[] verifierBytes = new byte[] {
                116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
                187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
                132, 141, 121
            };

            var verifier = TeslaAuthHelper.Base64UrlEncode(verifierBytes);
            Assert.AreEqual(verifier, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            Assert.AreEqual("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", TeslaAuthHelper.Challenge(verifier));
        }

        [TestMethod]
        public void VerifierLengthTest()
        {
            // This is a very simple test, to make sure the length of the code verifier matches what we expect it to be.
            // Length test cases from the end of here:
            // https://www.mickf.net/tech/oauth-pkce-swift-secure-code-verifiers-and-code-challenges/
            // 32 octets may require 43 bytes.
            var codeVerifier43 = TeslaAuthHelper.Base64UrlEncode(TeslaAuthHelper.GetBytes(TeslaAuthHelper.RandomString(32)));
            Assert.AreEqual(43, codeVerifier43.Length);

            var codeVerifier128 = TeslaAuthHelper.Base64UrlEncode(TeslaAuthHelper.GetBytes(TeslaAuthHelper.RandomString(96)));
            Assert.AreEqual(128, codeVerifier128.Length);
        }
        [TestMethod]
        public void OwnerApiLoginUrlTest()
        {
            var auth = new TeslaAuthHelper();
            var url = auth.GetLoginUrlForBrowser();
            var uri = new Uri(url);
            var q = HttpUtility.ParseQueryString(uri.Query);
            Assert.AreEqual("https", uri.Scheme);
            Assert.AreEqual("auth.tesla.com", uri.Host);
            Assert.AreEqual("/oauth2/v3/authorize", uri.AbsolutePath);
            Assert.AreEqual("ownerapi", q["client_id"]);
            Assert.IsTrue( q["code_challenge"]?.Length > 0);
            Assert.AreEqual("S256", q["code_challenge_method"]);
            Assert.AreEqual("https://auth.tesla.com/void/callback", q["redirect_uri"]);
            Assert.AreEqual("code", q["response_type"]);
        }

        [TestMethod]
        public void FleetApiLoginUrlTest()
        {
            var clientId = "MYCLIENT";
            var clientSecret = "MYSECRET";
            var redirectUrl = "MYURL://REDIRECT";
            var scopes = "SCOPE1 SCOPE2";

            var auth = new TeslaAuthHelper(TeslaAccountRegion.USA, clientId, clientSecret, redirectUrl, scopes);
            var url = auth.GetLoginUrlForBrowser();
            var uri = new Uri(url);
            var q = HttpUtility.ParseQueryString(uri.Query);
            Assert.AreEqual("https", uri.Scheme);
            Assert.AreEqual("auth.tesla.com", uri.Host);
            Assert.AreEqual("/oauth2/v3/authorize", uri.AbsolutePath);
            Assert.AreEqual(clientId, q["client_id"]);
            Assert.IsTrue(q["code_challenge"]?.Length > 0);
            Assert.AreEqual("S256", q["code_challenge_method"]);
            Assert.AreEqual(redirectUrl, q["redirect_uri"]);
            Assert.AreEqual(scopes, q["scope"]);
            Assert.AreEqual("code", q["response_type"]);
        }

        [TestMethod]
        public async Task ErrorsExtractedFromRedirectUrl()
        {
            var clientId = "MYCLIENT";
            var clientSecret = "MYSECRET";
            var redirectUrl = "MYURL://REDIRECT";
            var scopes = "SCOPE1 SCOPE2";

            var auth = new TeslaAuthHelper(TeslaAccountRegion.USA, clientId, clientSecret, redirectUrl, scopes);

            var loginRedirectUrl = "MYURL://REDIRECT?error=login_cancelled&error_description=User%20cancelled%20login&state=iKz0zKUNddyE9Qpy1J6O";
            try
            {
                await auth.GetTokenAfterLoginAsync(loginRedirectUrl);
                Assert.Fail("Exception expected");
            }
            catch (InvalidOperationException ex)
            {
                Assert.AreEqual(ex.Message, "Login failed with error 'login_cancelled'\r\nUser cancelled login");
            }
        }
    }
}
