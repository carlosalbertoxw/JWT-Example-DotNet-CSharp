using System.Security.Claims;
using System.Text.Json;

namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Utilidades para leer los claims de un JWT del lado del cliente.
    /// No valida la firma: eso es responsabilidad de la API. Aquí solo se
    /// extrae el contenido para construir el <see cref="ClaimsPrincipal"/> de
    /// Blazor y para saber si el access token ya expiró.
    /// </summary>
    public static class JwtParser
    {
        /// <summary>Extrae los claims del payload de un JWT.</summary>
        public static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var claims = new List<Claim>();

            string[] parts = jwt.Split('.');
            if (parts.Length < 2)
                return claims;

            byte[] payloadBytes = ParseBase64WithoutPadding(parts[1]);
            var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadBytes);
            if (payload is null)
                return claims;

            foreach (var kvp in payload)
            {
                if (kvp.Value.ValueKind == JsonValueKind.Array)
                {
                    // Claims con múltiples valores (p. ej. varios roles).
                    foreach (JsonElement item in kvp.Value.EnumerateArray())
                        claims.Add(new Claim(kvp.Key, item.ToString()));
                }
                else
                {
                    claims.Add(new Claim(kvp.Key, kvp.Value.ToString()));
                }
            }

            return claims;
        }

        /// <summary>
        /// Indica si el token está expirado (o no tiene claim "exp").
        /// </summary>
        public static bool IsExpired(string jwt, int skewSeconds = 0)
        {
            try
            {
                foreach (Claim claim in ParseClaimsFromJwt(jwt))
                {
                    if (claim.Type == "exp" && long.TryParse(claim.Value, out long exp))
                    {
                        DateTimeOffset expiry = DateTimeOffset.FromUnixTimeSeconds(exp);
                        return DateTimeOffset.UtcNow >= expiry.AddSeconds(-skewSeconds);
                    }
                }

                // Sin claim de expiración se considera no confiable.
                return true;
            }
            catch
            {
                return true;
            }
        }

        private static byte[] ParseBase64WithoutPadding(string base64)
        {
            // Convierte de Base64Url a Base64 estándar y restaura el padding.
            base64 = base64.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }
    }
}
