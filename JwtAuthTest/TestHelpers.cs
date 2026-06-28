using JwtAuth.Configuration;

namespace JwtAuthTest
{
    /// <summary>Utilidades compartidas por las pruebas.</summary>
    internal static class TestHelpers
    {
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
    }
}
