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

        public static void HandleLogin(HttpContext context)
        {
            //If there is a token in session, we try to validate it
            TryUserTokenAuthentication(context);

            if (context.User.Identity.IsAuthenticated)
                return;

            //If user auth failed
            if (Settings.ClientAuthenticationParameters.AuthFailUrl != null && context.Request.Url.ToString().Contains(Settings.ClientAuthenticationParameters.AuthFailUrl))
                return;

            //If request is callback from Oidc provider login page
            if (context.Request.Url.ToString().Contains(Settings.ClientAuthenticationParameters.CallbackUrl)
                && context.Request.QueryString["code"] != null && context.Request.QueryString["state"] != null //Request must have a code and state
                && context.Session[STATE_SESSION_KEY] != null && context.Session[STATE_SESSION_KEY].ToString() == context.Request.QueryString["state"])//State must match send state
            {
                string code = context.Request.QueryString["code"].ToString();

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
                    return;
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
                        return;
                    }

                }

                return;

            }


            //If user isn't authentified
            var state = GetState();

            context.Session[STATE_SESSION_KEY] = state;
            context.Session[FINALCALLBACK_SESSION_KEY] = context.Request.Url;

            //We redirect to OIDC
            context.ApplicationInstance.Response.Redirect(BuildAuthorizationRequest(state));
        }

        public static IList<SecurityKey> GetSigningKeysFromUrl(string url)
        {
            using (var cli = new WebClient())
            {
                var json_data = string.Empty;

                json_data = cli.DownloadString(url);

                return GetSigningKeysFromJson(json_data);
            }
        }

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

        private static string BuildAuthorizationRequest(string state)
        {
            return Settings.ProviderConfiguration.AuthorizationEndpointUrl + ToQueryString(GetAuthorizationRequestContent(state));
        }

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


    }

}
