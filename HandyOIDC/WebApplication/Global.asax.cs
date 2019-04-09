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

                ClientAuthenticationParameters = new HandyOidcClientAuthenticationParameters()
                {
                    CallbackUrl = "http://localhost:63835/callback",
                    AuthFailUrl = "http://localhost:63835/Home/Fail",
                },
                ProviderConfiguration = new HandyOidcProviderConfiguration()
                {
                    AuthorizationEndpointUrl = "https://dev-oh98gwym.eu.auth0.com/authorize",
                    TokenEndpointUrl = "https://dev-oh98gwym.eu.auth0.com/oauth/token",
                    ClientId = "kki6oRVaHMI1YByFVPmPqg6Qr3NskT8o",
                    ClientSecret = "kiqAajoebizqoTRGwt8Mmkvgcjs9Wkj8sp959pz9ja9M0dJ3XO7ldegnLvH_RoUk",
                    TokenEndPointAuthicationMethod = TokenEndPointAuthicationMethod.Post,
                    Scope = new string[] { "mail" },
                    TokenValidationParameters = new HandyOidcTokenValidationParameters()
                    {
                        //IssuerSigningKeys = HandyOidc.GetSigningKeysFromJson("{\"keys\":[{\"alg\":\"RS256\",\"kty\":\"RSA\",\"use\":\"sig\",\"x5c\":[\"MIIDDTCCAfWgAwIBAgIJXct2PZ3H1hUhMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi1vaDk4Z3d5bS5ldS5hdXRoMC5jb20wHhcNMTkwNDAyMTMxMzUxWhcNMzIxMjA5MTMxMzUxWjAkMSIwIAYDVQQDExlkZXYtb2g5OGd3eW0uZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8goeTQwmRIOhOCwEaD5Jk0XTYcipwhcYCp+N5uWK1PjjIHE4wZuNzzUziuXZloUbzsEWfl5jktapUZgBnlGfLZtBByRFFEj05tLRFwOLlPxYQMbb7Z/UtWuj1V1WUX7H+Ykko4PgLmMQgDp9XCg/ZmtV41v9RixpR38CiL9abmTNBVpsWJE43Y5P+KZ/U7U71PdcbkA1uFHK1iIOfArpwdSpUQuan6njuUvsnzS5dTd/yd5LLUukxV09RdBU730ODFXj5M3kdFZrPTRy0KibipyVe+ZSstAG627GfI3WFIhODsFEHeBzJKjPkgnjCO1XRIuATQBTEFxC3FXFMmCCbwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTlS/gpINSf5ubPMdAcZVofVgkNkjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAGxDmxz23vaT6ZOk62oYh+7LvwLeKiomyBIdovfxvfDTlHq2tbiRlyFadU3iFdIrcEr90f9AwwAvYhrAlOJ6/7/l6fRiWQlw+b/+w/12+CGkHhp9heImqg1/cBV6L96tQK2jQMRfubOaZimlFcTwf+YXZl06XFmMxELksaC/gYhtY7c8l+f+SATdMyFRVcy/1nAtWgixFxOMUyZcqVPRm4oR6zbHCIL0S+xucq8fdNaNMNYY6hF9lNqQNMLE0a2HhxHBTDqmgL11z29THhU3mK4ohm6nKu8SL/litb5ggG6l4jQrBzcNDladTvMNC5lWT+E11VxzFxH/Z0HiZhTMOVQ=\"],\"n\":\"8goeTQwmRIOhOCwEaD5Jk0XTYcipwhcYCp-N5uWK1PjjIHE4wZuNzzUziuXZloUbzsEWfl5jktapUZgBnlGfLZtBByRFFEj05tLRFwOLlPxYQMbb7Z_UtWuj1V1WUX7H-Ykko4PgLmMQgDp9XCg_ZmtV41v9RixpR38CiL9abmTNBVpsWJE43Y5P-KZ_U7U71PdcbkA1uFHK1iIOfArpwdSpUQuan6njuUvsnzS5dTd_yd5LLUukxV09RdBU730ODFXj5M3kdFZrPTRy0KibipyVe-ZSstAG627GfI3WFIhODsFEHeBzJKjPkgnjCO1XRIuATQBTEFxC3FXFMmCCbw\",\"e\":\"AQAB\",\"kid\":\"Q0Q1M0E2N0JFN0ZEQ0FBRjA2MDEzMzlEOTk4NjU5OEMxREIwQzYwOQ\",\"x5t\":\"Q0Q1M0E2N0JFN0ZEQ0FBRjA2MDEzMzlEOTk4NjU5OEMxREIwQzYwOQ\"}]}"),
                        IssuerSigningKeys = HandyOidc.GetSigningKeysFromUrl("https://dev-oh98gwym.eu.auth0.com/.well-known/jwks.json"),
                        ValidIssuer = "https://dev-oh98gwym.eu.auth0.com/",
                        ValidAudiences = new[] { "kki6oRVaHMI1YByFVPmPqg6Qr3NskT8o" }
                    }
                }

            });

        }


        protected void Application_AcquireRequestState(Object sender, EventArgs e)
        {

            HandyOidc.HandleLogin(HttpContext.Current);

        }

    }
}
