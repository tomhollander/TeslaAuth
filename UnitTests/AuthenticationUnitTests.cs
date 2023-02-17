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
            // https://bootstragram.com/blog/oauth-pkce-swift-secure-code-verifiers-and-code-challenges/

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
            // https://bootstragram.com/blog/oauth-pkce-swift-secure-code-verifiers-and-code-challenges/
            // 32 octets may require 43 bytes.
            var codeVerifier43 = TeslaAuthHelper.Base64UrlEncode(TeslaAuthHelper.GetBytes(TeslaAuthHelper.RandomString(32)));
            Assert.AreEqual(43, codeVerifier43.Length);

            var codeVerifier128 = TeslaAuthHelper.Base64UrlEncode(TeslaAuthHelper.GetBytes(TeslaAuthHelper.RandomString(96)));
            Assert.AreEqual(128, codeVerifier128.Length);
        }
    }
}
