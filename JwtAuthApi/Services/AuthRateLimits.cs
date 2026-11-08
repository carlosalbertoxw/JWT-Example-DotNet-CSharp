using JwtAuth.Security;

namespace JwtAuthApi.Services
{
    /// <summary>
    /// Límites de intentos de los endpoints de autenticación.
    /// </summary>
    /// <param name="Account">Límite estricto por cuenta (fuerza bruta contra un usuario).</param>
    /// <param name="Ip">Límite más holgado por IP ("password spraying" contra muchas cuentas).</param>
    public record AuthRateLimits(RateLimiter Account, RateLimiter Ip);

    /// <summary>Sección "RateLimit" de appsettings.json.</summary>
    public class RateLimitOptions
    {
        public const string SectionName = "RateLimit";

        public int AccountMaxAttempts { get; set; } = 5;

        public int IpMaxAttempts { get; set; } = 20;

        public int WindowSeconds { get; set; } = 900;
    }
}
