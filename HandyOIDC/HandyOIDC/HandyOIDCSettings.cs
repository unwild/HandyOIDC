namespace HandyOIDC
{
    public class HandyOIDCSettings
    {
        public string AuthorizationEndpointURL { get; set; }

        public string TokenEndpointURL { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string CallbackURL { get; set; }

        public string Scope { get; set; } = "openid";

        public string AuthFailURL { get; set; } = null;
    }
}
