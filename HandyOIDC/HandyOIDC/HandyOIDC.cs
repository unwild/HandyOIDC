using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Web;

namespace HandyOIDC
{

    public static class HandyOidc
    {

        private static HandyOidcSettings Settings;
        private static readonly HttpClient client = new HttpClient();


        public static void Init(HandyOidcSettings settings)
        {
            Settings = settings;
        }

        public static void HandleLogin(HttpContext context)
        {

            //TODO check si besoin de reload le token

            //If user auth failed
            if (Settings.ClientAuthenticationParameters.AuthFailUrl != null && context.Request.Url.ToString().Contains(Settings.ClientAuthenticationParameters.AuthFailUrl))
                return;


            if (context.Request.Url.ToString().Contains(Settings.ClientAuthenticationParameters.CallbackUrl)
                && context.Request.QueryString["code"] != null && context.Request.QueryString["state"] != null //Request must have a code and state
                && context.Session["OIDC_State"] != null && context.Session["OIDC_State"].ToString() == context.Request.QueryString["state"])//State must match send state
            {
                string code = context.Request.QueryString["code"].ToString();

                //Requesting token
                HttpResponseMessage response = TryGetToken(code, context);

                if (response.IsSuccessStatusCode)
                {
                    string jsonString = response.Content.ReadAsStringAsync().Result;

                    TokenEndPointResponseModel responseModel = JsonConvert.DeserializeObject<TokenEndPointResponseModel>(jsonString);

                    var handler = new JwtSecurityTokenHandler();

                    var principal = handler.ValidateToken(
                        responseModel.id_token,
                        Settings.ProviderConfiguration.TokenValidationParameters.ToTokenValidationParameters(),
                        out SecurityToken securityToken);


                    //Store securityToken in session

                    HttpContext.Current.User = principal;
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

            var state = GetState();
            context.Session["OIDC_State"] = state;

            //We redirect to OIDC
            context.ApplicationInstance.Response.Redirect(BuildAuthorizationRequest(state));
        }

        public static IList<SecurityKey> GetSigningKeys()
        {
            IList<SecurityKey> keys = new List<SecurityKey>();

            //TODO if null or empty, use the JkwsUrl to get JwksJson
            if (!string.IsNullOrEmpty(Settings.ProviderConfiguration.TokenValidationParameters.JwksJson))
            {

                JsonWebKeySet keyset = JsonConvert.DeserializeObject<JsonWebKeySet>(Settings.ProviderConfiguration.TokenValidationParameters.JwksJson);

                foreach (SecurityKey key in keyset.GetSigningKeys())
                {
                    keys.Add(key);
                }
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

    }

}
