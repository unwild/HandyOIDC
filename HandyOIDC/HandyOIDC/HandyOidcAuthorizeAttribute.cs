using System.Web;
using System.Web.Mvc;

namespace HandyOIDC
{
    public class HandyOidcAuthorizeAttribute : AuthorizeAttribute
    {

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            HandyOidc.HandleLogin(HttpContext.Current);
        }

    }
}
