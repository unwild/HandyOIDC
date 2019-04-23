using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Web;

namespace HandyOIDC
{

    public static class HandyOidc
    {
        readonly static string STATE_SESSION_KEY = "HandyOidc_User_State";
        readonly static string JWT_SESSION_KEY = "HandyOidc_User_Jwt";
        readonly static string FINALCALLBACK_SESSION_KEY = "HandyOidc_User_FinalCallback";

        private static HandyOidcSettings Settings;
        private static readonly HttpClient client = new HttpClient();


        public static void Init(HandyOidcSettings settings)
        {
            Settings = settings;
        }

        /// <summary>
        /// Do not use call ! It is called by the HandyOidcAuthorizeAttribute
        /// Handle user login from start to end based on settings
        /// </summary>
        /// <param name="context"></param>
        public static void HandleLogin(HttpContext context)
        {
            //If there is a token in session, we try to validate it
            TryUserTokenAuthentication(context);

            //if user is directed to login page
            if (IsLoginPageRequest(context))
                return; //continue


            //if user is logging out
            if (IsLogoutPageRequest(context))
            {
                Logout(context);
                return;
            }


            //If user is connected, continue
            if (context.User != null && context.User.Identity.IsAuthenticated)
                return;


            //If user auth failed
            if (IsAuthFailPageRequest(context))
                return;


            //If request is callback from Oidc provider login page
            if (IsValidCallback(context))
            {
                string code = context.Request.QueryString["code"].ToString();

                HandleCallback(context, code);

                return;
            }


            //If user isn't authentified
            var state = GetState();

            context.Session[STATE_SESSION_KEY] = state;
            context.Session[FINALCALLBACK_SESSION_KEY] = context.Request.Url;

            //if login page is not defined
            if (Settings.ClientAuthenticationParameters.LoginUrl == null)
                Login(context);
            else
                context.ApplicationInstance.Response.Redirect(Settings.ClientAuthenticationParameters.LoginUrl); //We redirect to login page

        }

        public static void Login(HttpContext context)
        {
            context.ApplicationInstance.Response.Redirect(BuildAuthorizationRequest(context.Session[STATE_SESSION_KEY].ToString())); //We redirect to OIDC provider
        }


        /// <summary>
        /// Returns all signing keys from jkws.json file Url
        /// </summary>
        /// <param name="url">jwks.json file Url</param>
        /// <returns></returns>
        public static IList<SecurityKey> GetSigningKeysFromUrl(string url)
        {
            using (var cli = new WebClient())
            {
                var json_data = string.Empty;

                json_data = cli.DownloadString(url);

                return GetSigningKeysFromJson(json_data);
            }
        }

        /// <summary>
        /// Return all signing keys from jwks.json file content
        /// </summary>
        /// <param name="jsonString">full json string from jwks.json</param>
        /// <returns></returns>
        public static IList<SecurityKey> GetSigningKeysFromJson(string jsonString)
        {
            IList<SecurityKey> keys = new List<SecurityKey>();

            JsonWebKeySet keyset = JsonConvert.DeserializeObject<JsonWebKeySet>(jsonString);

            foreach (SecurityKey key in keyset.GetSigningKeys())
            {
                keys.Add(key);
            }


            return keys;
        }


        /* Private members */


        /// <summary>
        /// Try to get the token from callback request and storing it in session
        /// If token is valid, the user will be redirected to his original requested url
        /// </summary>
        /// <param name="context">Current HttpContext</param>
        /// <param name="code">Callback code</param>
        private static void HandleCallback(HttpContext context, string code)
        {

            //Requesting token
            HttpResponseMessage response = TryGetToken(code, context);

            if (response.IsSuccessStatusCode)
            {
                string jsonString = response.Content.ReadAsStringAsync().Result;

                TokenEndPointResponseModel responseModel = JsonConvert.DeserializeObject<TokenEndPointResponseModel>(jsonString);

                var handler = new JwtSecurityTokenHandler();

                var securityToken = handler.ReadJwtToken(responseModel.id_token);

                //Store securityToken in session
                context.Session[JWT_SESSION_KEY] = securityToken;

                //redirect to original destination
                context.ApplicationInstance.Response.Redirect(context.Session[FINALCALLBACK_SESSION_KEY].ToString());
            }
            else
            {
                if (Settings.ClientAuthenticationParameters.AuthFailUrl != null)
                {
                    context.ApplicationInstance.Response.Redirect(Settings.ClientAuthenticationParameters.AuthFailUrl);
                }
                else
                {
                    context.ApplicationInstance.Response.Clear();
                    context.ApplicationInstance.Response.Write("Access Denied");
                    context.ApplicationInstance.Response.StatusCode = 401;
                    context.ApplicationInstance.Response.End();
                }

            }
        }

        /// <summary>
        /// Logout user
        /// If login Url is defined, will redirect to login page
        /// </summary>
        /// <param name="context">Current HttpContext</param>
        private static void Logout(HttpContext context)
        {
            context.Session.Clear();
            context.User = null;

            if (Settings.ClientAuthenticationParameters.LoginUrl != null)
                context.ApplicationInstance.Response.Redirect(Settings.ClientAuthenticationParameters.LoginUrl + "?logout=true");
        }

        /// <summary>
        /// Token request 
        /// </summary>
        /// <param name="code"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        private static HttpResponseMessage TryGetToken(string code, HttpContext context)
        {
            context.ApplicationInstance.Response.Clear();

            if (Settings.ProviderConfiguration.TokenEndPointAuthicationMethod == TokenEndPointAuthicationMethod.Basic)
                context.ApplicationInstance.Response.Headers.Add("Authorization", GetAuthorizationHeader());

            HttpContent content = new FormUrlEncodedContent(GetTokenRequestContent(code));
            content.Headers.Clear();
            content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");

            return client.PostAsync(BuildTokenRequest(code), content).Result;

        }

        /// <summary>
        /// Return authorisation request Url string with parameters
        /// </summary>
        /// <param name="state">generated state for the current user</param>
        /// <returns></returns>
        private static string BuildAuthorizationRequest(string state)
        {
            return Settings.ProviderConfiguration.AuthorizationEndpointUrl + ToQueryString(GetAuthorizationRequestContent(state));
        }

        /// <summary>
        /// Build token request Url string with parameters
        /// </summary>
        /// <param name="code">callback code from current user</param>
        /// <returns></returns>
        private static string BuildTokenRequest(string code)
        {
            return Settings.ProviderConfiguration.TokenEndpointUrl + ToQueryString(GetTokenRequestContent(code));
        }


        private static IEnumerable<KeyValuePair<string, string>> GetAuthorizationRequestContent(string state)
        {
            return new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("client_id", Settings.ProviderConfiguration.ClientId),
                new KeyValuePair<string, string>("redirect_uri", Settings.ClientAuthenticationParameters.CallbackUrl),
                new KeyValuePair<string, string>("response_type", "code"),
                new KeyValuePair<string, string>("scope", GetScopeString()),
                new KeyValuePair<string, string>("state", state)
            };
        }

        private static IEnumerable<KeyValuePair<string, string>> GetTokenRequestContent(string code)
        {
            var content = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", Settings.ClientAuthenticationParameters.CallbackUrl),
            };

            if (Settings.ProviderConfiguration.TokenEndPointAuthicationMethod == TokenEndPointAuthicationMethod.Post)
            {
                content.Add(new KeyValuePair<string, string>("client_id", Settings.ProviderConfiguration.ClientId));
                content.Add(new KeyValuePair<string, string>("client_secret", Settings.ProviderConfiguration.ClientSecret));
            }

            return content;
        }


        /* Utils */


        /// <summary>
        /// Is the current HttpContext.Request a valid callback from OIDC provider ?
        /// </summary>
        /// <param name="context">Current HttpContext</param>
        /// <returns></returns>
        private static bool IsValidCallback(HttpContext context)
        {
            return (string.Equals(GetCleanRoute(context), Settings.ClientAuthenticationParameters.CallbackUrl, StringComparison.OrdinalIgnoreCase) //Url matches
                && context.Request.QueryString["code"] != null && context.Request.QueryString["state"] != null //Request must have a code and state
                && context.Session[STATE_SESSION_KEY] != null && context.Session[STATE_SESSION_KEY].ToString() == context.Request.QueryString["state"]);//State must match send state
        }

        private static string ToQueryString(IEnumerable<KeyValuePair<string, string>> values)
        {
            var content = values.Select(v => $"{HttpUtility.UrlEncode(v.Key)}={HttpUtility.UrlEncode(v.Value)}");
            return "?" + string.Join("&", content);

        }

        private static string GetAuthorizationHeader()
        {
            return "Basic " + Convert.ToBase64String(System.Text.Encoding.GetEncoding("ISO-8859-1").GetBytes(Settings.ProviderConfiguration.ClientId + ":" + Settings.ProviderConfiguration.ClientSecret));
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

        private static void TryUserTokenAuthentication(HttpContext context)
        {
            JwtSecurityToken token = context.Session[JWT_SESSION_KEY] != null ? context.Session[JWT_SESSION_KEY] as JwtSecurityToken : null;

            if (token == null)
                return;

            //If token has expired
            if (token.ValidTo < DateTime.Now)
                Logout(context);

            var handler = new JwtSecurityTokenHandler();

            var principal = handler.ValidateToken(token.RawData, Settings.ProviderConfiguration.TokenValidationParameters.ToTokenValidationParameters(), out SecurityToken securityToken);

            context.User = principal;
        }

        private static string GetScopeString()
        {
            string scope = string.Empty;

            if (!Settings.ProviderConfiguration.Scope.Contains("openid", StringComparer.OrdinalIgnoreCase))
                scope = "openid ";

            return scope + string.Join(" ", Settings.ProviderConfiguration.Scope);

        }

        private static string GetCleanRoute(HttpContext context)
        {
            Uri url = context.Request.Url;
            return string.Format("{0}{1}{2}{3}", url.Scheme, Uri.SchemeDelimiter, url.Authority, url.AbsolutePath);
        }


        private static bool IsLoginPageRequest(HttpContext context)
        {
            return !string.IsNullOrEmpty(Settings.ClientAuthenticationParameters.LoginUrl)
                && string.Equals(GetCleanRoute(context), Settings.ClientAuthenticationParameters.LoginUrl, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsLogoutPageRequest(HttpContext context)
        {
            return !string.IsNullOrEmpty(Settings.ClientAuthenticationParameters.LogoutUrl)
                && string.Equals(GetCleanRoute(context), Settings.ClientAuthenticationParameters.LogoutUrl, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsAuthFailPageRequest(HttpContext context)
        {
            return !string.IsNullOrEmpty(Settings.ClientAuthenticationParameters.AuthFailUrl)
                && string.Equals(GetCleanRoute(context), Settings.ClientAuthenticationParameters.AuthFailUrl, StringComparison.OrdinalIgnoreCase);
        }


    }

}
