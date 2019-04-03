namespace HandyOIDC
{
    public class HandyOIDCSettings
    {
        public string AuthorizationURL { get; set; }

        public string TokenURL { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string CallbackURL { get; set; }

        public string Scope { get; set; } = "openid";

        public string AuthFailURL { get; set; } = null;
    }
}
