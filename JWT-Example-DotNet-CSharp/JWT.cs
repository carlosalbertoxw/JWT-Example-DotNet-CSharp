
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_Example_DotNet_CSharp
{
    public class JWT
    {
        public String CreateJWT(string username, string issuer, string audience, string key, long SecondsToExpire)
        {
            try
            {
                var header = new JwtHeader(new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha512));
                var payload = new JwtPayload();

                payload.Add("username", username);
                payload.Add("iss", issuer);
                payload.Add("aud", audience);
                payload.Add("iat", (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds);
                payload.Add("nbf", (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds);
                payload.Add("exp", (DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds + SecondsToExpire);

                JwtSecurityToken jst = new JwtSecurityToken(header, payload);
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                return tokenHandler.WriteToken(jst);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }

        public String VerifyJWT(string token, string issuer, string audience, string key)
        {
            try
            {
                var jwtHandler = new JwtSecurityTokenHandler();
                var readableToken = jwtHandler.CanReadToken(token);
                if (readableToken == true)
                {
                    var validationParameters = new TokenValidationParameters()
                    {
                        RequireExpirationTime = true,
                        ValidateLifetime = true,
                        ValidateIssuer = true,
                        ValidIssuer = issuer,
                        ValidateAudience = true,
                        ValidAudience = audience,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
                    };

                    SecurityToken securityToken;
                    var principal = jwtHandler.ValidateToken(token, validationParameters, out securityToken);

                    foreach (Claim c in principal.Claims)
                    {
                        if (c.Type == "username")
                        {
                            return c.Value;
                        }
                    }
                }
                return String.Empty;
            }
            catch(Exception ex)
            {
                throw new Exception(ex.Message, ex);
            }
        }
    }
}
