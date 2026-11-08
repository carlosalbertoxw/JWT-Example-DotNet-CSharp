using System.Security.Cryptography;
using System.Text;
using JwtAuth.Configuration;
using JwtAuth.Models;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Tokens
{
    /// <summary>
    /// Implementación de <see cref="ITokenService"/> basada en
    /// <see cref="JsonWebTokenHandler"/> (el manejador recomendado, el mismo que usa
    /// JwtBearer para validar) y firma simétrica HMAC-SHA256.
    /// </summary>
    /// <remarks>
    /// Claims del access token (contrato común de los ejemplos): <c>sub</c> (id del
    /// usuario), <c>username</c>, <c>role</c>, <c>iss</c>, <c>aud</c>, <c>iat</c>,
    /// <c>nbf</c>, <c>exp</c> y <c>jti</c>.
    /// </remarks>
    public class TokenService : ITokenService
    {
        public const string UsernameClaim = "username";
        public const string RoleClaim = "role";

        private readonly JwtSettings _settings;
        private readonly SymmetricSecurityKey _signingKey;
        private readonly TimeProvider _time;
        private readonly JsonWebTokenHandler _handler = new();

        public TokenService(JwtSettings settings) : this(settings, TimeProvider.System)
        {
        }

        public TokenService(JwtSettings settings, TimeProvider time)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _time = time;
            _signingKey = CreateSigningKey(settings);
        }

        public string CreateAccessToken(AppUser user)
        {
            ArgumentNullException.ThrowIfNull(user);

            DateTime now = _time.GetUtcNow().UtcDateTime;
            DateTime expires = now.AddMinutes(_settings.AccessTokenMinutes);

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = _settings.Issuer,
                Audience = _settings.Audience,
                IssuedAt = now,
                // notBefore un segundo antes: permite tiempos de vida muy cortos
                // (útil en pruebas) sin violar "expires posterior a notBefore".
                NotBefore = now.AddSeconds(-1),
                Expires = expires,
                Claims = new Dictionary<string, object>
                {
                    [JwtRegisteredClaimNames.Sub] = user.Id.ToString(),
                    [UsernameClaim] = user.Username,
                    [RoleClaim] = user.Role,
                    [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString()
                },
                SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256)
            };

            return _handler.CreateToken(descriptor);
        }

        /// <summary>Refresh token opaco: 32 bytes aleatorios en hexadecimal (64 caracteres).</summary>
        public string GenerateRefreshToken() =>
            Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

        /// <summary>
        /// Construye los parámetros de validación a partir de la configuración,
        /// sin necesidad de instanciar el servicio. Permite a la capa de API
        /// configurar el bearer reutilizando exactamente la misma lógica (única
        /// fuente de verdad) durante el arranque.
        /// </summary>
        public static TokenValidationParameters CreateValidationParameters(JwtSettings settings)
        {
            ArgumentNullException.ThrowIfNull(settings);
            return CreateValidationParameters(settings, CreateSigningKey(settings));
        }

        private static SymmetricSecurityKey CreateSigningKey(JwtSettings settings)
        {
            if (string.IsNullOrWhiteSpace(settings.SigningKey))
                throw new ArgumentException("La clave de firma (SigningKey) no puede estar vacía.", nameof(settings));

            byte[] keyBytes = Encoding.UTF8.GetBytes(settings.SigningKey);
            if (keyBytes.Length < JwtSettings.MinSigningKeyBytes)
                throw new ArgumentException(
                    $"La clave de firma debe tener al menos {JwtSettings.MinSigningKeyBytes} bytes para HMAC-SHA256.",
                    nameof(settings));

            return new SymmetricSecurityKey(keyBytes);
        }

        private static TokenValidationParameters CreateValidationParameters(
            JwtSettings settings, SymmetricSecurityKey signingKey) => new()
            {
                ValidateIssuer = true,
                ValidIssuer = settings.Issuer,
                ValidateAudience = true,
                ValidAudience = settings.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromSeconds(settings.ClockSkewSeconds),
                // Los claims conservan sus nombres cortos del contrato (sub, username, role).
                NameClaimType = UsernameClaim,
                RoleClaimType = RoleClaim
            };
    }
}
