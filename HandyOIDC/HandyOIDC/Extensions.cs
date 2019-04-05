using Microsoft.IdentityModel.Tokens;

namespace HandyOIDC
{
    public static class Extensions
    {

        public static TokenValidationParameters ToTokenValidationParameters(this HandyOidcTokenValidationParameters parms)
        {

            return new TokenValidationParameters()
            {
                ValidIssuer = parms.ValidIssuer,
                ValidAudiences = parms.ValidAudiences,
                IssuerSigningKeys = HandyOidc.GetSigningKeys(),
                AuthenticationType = "id_token"
            };

        }

    }
}
