using TeslaAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http.Extensions;

namespace Test.Web
{
    public static class TeslaAuthSingleton
    {
        private static TeslaAuthHelper instance;
        private static object lockObject = new object();

        public static TeslaAuthHelper GetInstance(IConfiguration config, HttpRequest request)
        {
 
            lock (lockObject)
            {
                if (instance == null) 
                {
                    var redirectUri = new Uri(new Uri(request.GetEncodedUrl()), "/redirect");
                    instance = new TeslaAuthHelper("TeslaAuthHelper/1.0", config.GetSection("TeslaAuth:ClientId").Value,
                        config.GetSection("TeslaAuth:ClientSecret").Value, redirectUri.AbsoluteUri, config.GetSection("TeslaAuth:Scope").Value);
                }
            }
            return instance;
        }
       
    }
}
