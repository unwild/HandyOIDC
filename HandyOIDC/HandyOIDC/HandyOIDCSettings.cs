using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

namespace HandyOIDC
{
    public enum TokenEndPointAuthicationMethod
    {
        Post,
        Basic
    }

    public class HandyOidcSettings
    {
        public HandyOidcClientAuthenticationParameters ClientAuthenticationParameters { get; set; }

        public HandyOidcProviderConfiguration ProviderConfiguration { get; set; }

    }

    public class HandyOidcClientAuthenticationParameters
    {
        /// <summary>
        /// Client callback url
        /// Doesnt' have to exist in your website
        /// </summary>
        public string CallbackUrl { get; set; }

        /// <summary>
        /// Url to redirect to if auth fails
        /// This page must allow anonymous [AllowAnonymous]
        /// </summary>
        public string AuthFailUrl { get; set; } = null;

        /// <summary>
        /// Login url, just a page with a page button, calling HandyOIDC.Connect();
        /// This page must allow anonymous [AllowAnonymous]
        /// </summary>
        public string LoginUrl { get; set; } = null;

        /// <summary>
        /// Logout Url
        /// This page must allow anonymous. If LoginUrl is defined, the user will be redirected to Login url
        /// </summary>
        public string LogoutUrl { get; set; } = null;
    }

    public class HandyOidcProviderConfiguration
    {
        public string AuthorizationEndpointUrl { get; set; }

        public string TokenEndpointUrl { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string[] Scope { get; set; } = new string[0];

        public TokenEndPointAuthicationMethod TokenEndPointAuthicationMethod { get; set; } = TokenEndPointAuthicationMethod.Basic;

        public HandyOidcTokenValidationParameters TokenValidationParameters { get; set; }

    }

    public class HandyOidcTokenValidationParameters
    {
        public string ValidIssuer { get; set; }

        public string[] ValidAudiences { get; set; }

        public IList<SecurityKey> IssuerSigningKeys { get; set; }

    }

}