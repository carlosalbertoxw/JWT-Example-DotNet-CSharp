using System.Security.Claims;
using JwtAuth.Configuration;
using JwtAuth.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace JwtAuthTest
{
    /// <summary>Utilidades compartidas por las pruebas.</summary>
    internal static class TestHelpers
    {
        /// <summary>Pocas iteraciones para que las pruebas corran rápido (el hash las guarda).</summary>
        public const int FastIterations = 1_000;

        public static JwtSettings CreateSettings(
            int accessTokenMinutes = 15,
            int refreshTokenDays = 7,
            int clockSkewSeconds = 0) => new()
            {
                Issuer = "TestIssuer",
                Audience = "TestAudience",
                SigningKey = "clave-de-pruebas-suficientemente-larga-1234567890",
                AccessTokenMinutes = accessTokenMinutes,
                RefreshTokenDays = refreshTokenDays,
                ClockSkewSeconds = clockSkewSeconds
            };

        /// <summary>
        /// Valida un access token igual que lo hace el middleware JwtBearer de la API
        /// (mismos parámetros de TokenService). Devuelve null si no es válido.
        /// </summary>
        public static async Task<ClaimsPrincipal?> ValidateAsync(string token, JwtSettings settings)
        {
            var result = await new JsonWebTokenHandler()
                .ValidateTokenAsync(token, TokenService.CreateValidationParameters(settings));
            return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
        }
    }

    /// <summary>Reloj controlable para simular el paso del tiempo.</summary>
    internal sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now += delta;
    }
}
