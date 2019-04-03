using System;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using HandyOIDC;

namespace WebApplication
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            HandyOIDC.HandyOIDC.Init(new HandyOIDCSettings()
            {
                AuthorizationEndpointURL = "https://myprovider.xyz/authorize",
                TokenEndpointURL = "https://myprovider.xyz/token",
                ClientId = "myclientid",
                ClientSecret = "myclientsecret",
                CallbackURL = "http://localhost:63835/callback"
            });

        }


        protected void Application_AcquireRequestState(Object sender, EventArgs e)
        {

            HandyOIDC.HandyOIDC.HandleLogin(HttpContext.Current);

        }

    }
}
