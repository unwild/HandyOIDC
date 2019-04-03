using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Web;

namespace HandyOIDC
{

    public static class HandyOidc
    {

        private static HandyOIDCSettings Settings;
        private static readonly HttpClient client = new HttpClient();


        public static void Init(HandyOIDCSettings settings)
        {
            Settings = settings;
        }

        public static void HandleLogin(HttpContext context)
        {
            //If user auth failed
            if (Settings.AuthFailURL != null && context.Request.Url.ToString().Contains(Settings.AuthFailURL))
                return;


            if (context.Request.Url.ToString().Contains(Settings.CallbackURL)
                && context.Request.QueryString["code"] != null && context.Request.QueryString["state"] != null //Request must have a code and state
                && context.Session["OIDC_State"] != null && context.Session["OIDC_State"].ToString() == context.Request.QueryString["state"])//State must match send state
            {
                string code = context.Request.QueryString["code"].ToString();

                HttpResponseMessage response = TryGetToken(code, context);

                if (response.IsSuccessStatusCode)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    if (Settings.AuthFailURL != null)
                    {
                        context.ApplicationInstance.Response.Redirect(Settings.AuthFailURL);
                    }
                    else
                    {
                        context.ApplicationInstance.Response.Clear();
                        context.ApplicationInstance.Response.Write("Access Denied");
                        context.ApplicationInstance.Response.StatusCode = 401;
                        context.ApplicationInstance.Response.End();
                        return;
                    }

                }

                return;

            }

            var state = GetState();
            context.Session["OIDC_State"] = state;

            //We redirect to OIDC
            context.ApplicationInstance.Response.Redirect(BuildAuthorizationRequest(state));
        }



        private static HttpResponseMessage TryGetToken(string code, HttpContext context)
        {
            context.ApplicationInstance.Response.Clear();

            context.ApplicationInstance.Response.Headers.Add("Authorization", GetAuthorizationHeader());

            HttpContent content = new FormUrlEncodedContent(GetTokenRequestContent(code));
            content.Headers.Clear();
            content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");

            return client.PostAsync(Settings.TokenEndpointURL, content).Result;

        }

        private static string BuildAuthorizationRequest(string state)
        {
            return Settings.AuthorizationEndpointURL + ToQueryString(GetAuthorizationRequestContent(state));
        }

        private static string BuildTokenRequest(string code)
        {
            return Settings.TokenEndpointURL + ToQueryString(GetTokenRequestContent(code));
        }


        private static IEnumerable<KeyValuePair<string, string>> GetAuthorizationRequestContent(string state)
        {
            return new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("client_id", Settings.ClientId),
                new KeyValuePair<string, string>("redirect_uri", Settings.CallbackURL),
                new KeyValuePair<string, string>("response_type", "code"),
                new KeyValuePair<string, string>("state", state)
            };
        }

        private static IEnumerable<KeyValuePair<string, string>> GetTokenRequestContent(string code)
        {
            return new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", Settings.CallbackURL),
            };
        }


        private static string ToQueryString(IEnumerable<KeyValuePair<string, string>> values)
        {
            var content = values.Select(v => $"{HttpUtility.UrlEncode(v.Key)}={HttpUtility.UrlEncode(v.Value)}");
            return "?" + string.Join("&", content);

        }

        private static string GetAuthorizationHeader()
        {
            return "Basic " + Convert.ToBase64String(System.Text.Encoding.GetEncoding("ISO-8859-1").GetBytes(Settings.ClientId + ":" + Settings.ClientSecret));
        }

        private static string GetState()
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[32];
                rng.GetBytes(tokenData);

                return Convert.ToBase64String(tokenData);
            }
        }
    }
}
