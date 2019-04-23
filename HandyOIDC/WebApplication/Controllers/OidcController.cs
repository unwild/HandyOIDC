using HandyOIDC;
using System.Web.Mvc;

namespace WebApplication.Controllers
{
    public class OidcController : Controller
    {
        [AllowAnonymous]
        public ActionResult Login(bool connect = false)
        {
            if (connect)
                HandyOidc.Login(System.Web.HttpContext.Current);

            return View();
        }

        public ActionResult Logout()
        {
            return View();
        }

        public ActionResult Callback()
        {
            return RedirectToAction("Index", "Home");
        }

        [AllowAnonymous]
        public ActionResult Fail()
        {
            return Content("Auth failed");
        }


    }
}