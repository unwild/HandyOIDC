using HandyOIDC;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace WebApplication
{
    public class MvcApplication : HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);


            HandyOidc.Init(new HandyOidcSettings()
            {
                AuthorizationEndpointURL = "https://dev-oh98gwym.eu.auth0.com/authorize",
                TokenEndpointURL = "https://dev-oh98gwym.eu.auth0.com/oauth/token",
                ClientId = "kki6oRVaHMI1YByFVPmPqg6Qr3NskT8o",
                ClientSecret = "kiqAajoebizqoTRGwt8Mmkvgcjs9Wkj8sp959pz9ja9M0dJ3XO7ldegnLvH_RoUk",
                CallbackURL = "http://localhost:63835/callback",
                AuthFailURL = "http://localhost:63835/Home/Fail",
                TokenEndPointAuthicationMethod = TokenEndPointAuthicationMethod.Post,
                TokenValidationParameters = new TokenValidationParameters()
                {

                }
            });

        }


        protected void Application_AcquireRequestState(Object sender, EventArgs e)
        {

            HandyOidc.HandleLogin(HttpContext.Current);

        }

    }
}
