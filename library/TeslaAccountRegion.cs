
namespace TeslaAuth
{
    /// <summary>
    /// Tesla accounts are tied to SSO servers in particular regions.
    /// </summary>
    /// <remarks>It is not clear how many regions Tesla supports.  As of Feb 2021, it appears to be China vs. the rest of the world.</remarks>
    public enum TeslaAccountRegion
    {
        Unknown,
        USA,
        China
    }
}
