using System;
using System.Runtime.Serialization;

namespace TeslaAuth
{
    /// <summary>
    /// Multi-factor authentication can fail in at least two ways:
    /// 1) MFA is required for an account and we didn't supply an MFA code
    /// 2) The MFA code entered is invalid or expired.
    /// </summary>
    public class MultiFactorAuthenticationException : Exception
    {
        public MultiFactorAuthenticationException() : base("Multi-factor authentication is required for this account")
        {
        }

        public MultiFactorAuthenticationException(String message) : base(message)
        {
        }

        public MultiFactorAuthenticationException(String message, String accountName) : base(message)
        {
            AccountName = accountName;
        }

        public String AccountName { get; set; }
    }
}
