namespace JwtAuth.Configuration
{
    /// <summary>
    /// Parámetros de configuración del sistema de tokens JWT.
    /// Se llena habitualmente desde la sección "Jwt" del appsettings.json.
    /// </summary>
    public class JwtSettings
    {
        /// <summary>Nombre de la sección de configuración asociada.</summary>
        public const string SectionName = "Jwt";

        /// <summary>Emisor del token (claim "iss").</summary>
        public string Issuer { get; set; } = string.Empty;

        /// <summary>Audiencia destino del token (claim "aud").</summary>
        public string Audience { get; set; } = string.Empty;

        /// <summary>
        /// Clave simétrica usada para firmar y validar los tokens.
        /// Debe tener al menos 32 bytes (256 bits) para HMAC-SHA256.
        /// </summary>
        public string SigningKey { get; set; } = string.Empty;

        /// <summary>Tiempo de vida del access token, en minutos.</summary>
        public int AccessTokenMinutes { get; set; } = 15;

        /// <summary>Tiempo de vida del refresh token, en días.</summary>
        public int RefreshTokenDays { get; set; } = 7;

        /// <summary>
        /// Tolerancia de reloj (en segundos) aplicada al validar la expiración.
        /// Se deja en 0 para que las pruebas de expiración sean deterministas.
        /// </summary>
        public int ClockSkewSeconds { get; set; } = 0;
    }
}
