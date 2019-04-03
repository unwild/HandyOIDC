namespace HandyOIDC
{
    public enum TokenEndPointAuthicationMethod
    {
        Post,
        Basic
    }

    public class HandyOIDCSettings
    {
        public string AuthorizationEndpointURL { get; set; }

        public string TokenEndpointURL { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string CallbackURL { get; set; }

        public string Scope { get; set; } = "openid";

        public string AuthFailURL { get; set; } = null;

        public TokenEndPointAuthicationMethod TokenEndPointAuthicationMethod { get; set; } = TokenEndPointAuthicationMethod.Basic;
    }
}
