using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TeslaAuth;

namespace Test.Web.Pages
{
    public class RedirectModel : PageModel
    {
        private readonly IConfiguration _configuration;

        public RedirectModel(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public Tokens Tokens { get; private set; }  
        public async Task<IActionResult> OnGetAsync()
        {
            if (Request.Query["code"].FirstOrDefault() != null) 
            {
                Tokens = await TeslaAuthSingleton.GetInstance(_configuration, Request).GetTokenAfterLoginAsync(Request.GetEncodedUrl());
            }
            return Page();
        }
    }
}
