using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace JwtAuthImplTest.Helpers
{
    /// <summary>
    /// Construye JWTs de prueba (sin firma válida; el parser cliente no la valida).
    /// Reproduce las claves de claims tal como las emite la JwtAuthApi: el nombre
    /// en "username" y los roles bajo la URI estándar <see cref="ClaimTypes.Role"/>.
    /// </summary>
    public static class TestJwt
    {
        public static string Create(
            string username = "tester",
            string[]? roles = null,
            DateTimeOffset? expires = null)
        {
            roles ??= new[] { "User" };
            long exp = (expires ?? DateTimeOffset.UtcNow.AddMinutes(15)).ToUnixTimeSeconds();

            var payload = new Dictionary<string, object>
            {
                ["sub"] = Guid.NewGuid().ToString(),
                ["username"] = username,
                [ClaimTypes.Role] = roles,
                ["exp"] = exp
            };

            return Segment(new { alg = "HS256", typ = "JWT" }) + "." + Segment(payload) + ".sig";
        }

        public static string Expired(string username = "tester", string[]? roles = null)
            => Create(username, roles, DateTimeOffset.UtcNow.AddMinutes(-5));

        /// <summary>Token sin claim "exp" (se debe tratar como no confiable).</summary>
        public static string WithoutExpiration(string username = "tester")
        {
            var payload = new Dictionary<string, object> { ["username"] = username };
            return Segment(new { alg = "HS256", typ = "JWT" }) + "." + Segment(payload) + ".sig";
        }

        private static string Segment(object value)
        {
            string json = JsonSerializer.Serialize(value);
            return Base64UrlEncode(Encoding.UTF8.GetBytes(json));
        }

        private static string Base64UrlEncode(byte[] bytes)
            => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
