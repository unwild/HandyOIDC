using Microsoft.IdentityModel.Tokens;

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
        public string CallbackUrl { get; set; }
        public string AuthFailUrl { get; set; } = null;
    }

    public class HandyOidcProviderConfiguration
    {
        public string AuthorizationEndpointUrl { get; set; }

        public string TokenEndpointUrl { get; set; }

        public string JwksUrl { get; set; }

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

        public string JwksJson { get; set; }
    }

}