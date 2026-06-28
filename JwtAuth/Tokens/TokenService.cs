using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuth.Configuration;
using JwtAuth.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Tokens
{
    /// <summary>
    /// Implementación de <see cref="ITokenService"/> basada en
    /// <see cref="JwtSecurityTokenHandler"/> y firma simétrica HMAC-SHA256.
    /// </summary>
    public class TokenService : ITokenService
    {
        private readonly JwtSettings _settings;
        private readonly SymmetricSecurityKey _signingKey;
        private readonly JwtSecurityTokenHandler _handler = new();

        public TokenService(JwtSettings settings)
        {
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));

            if (string.IsNullOrWhiteSpace(_settings.SigningKey))
                throw new ArgumentException("La clave de firma (SigningKey) no puede estar vacía.", nameof(settings));

            byte[] keyBytes = Encoding.UTF8.GetBytes(_settings.SigningKey);
            if (keyBytes.Length < 32)
                throw new ArgumentException("La clave de firma debe tener al menos 32 bytes para HMAC-SHA256.", nameof(settings));

            _signingKey = new SymmetricSecurityKey(keyBytes);
        }

        public (string Token, DateTime ExpiresAtUtc) CreateAccessToken(AppUser user)
        {
            ArgumentNullException.ThrowIfNull(user);

            DateTime now = DateTime.UtcNow;
            DateTime expires = now.AddMinutes(_settings.AccessTokenMinutes);

            // notBefore se ubica un segundo antes para que el token siga siendo
            // construible incluso con tiempos de vida muy cortos (útil en pruebas)
            // sin violar la regla "expires debe ser posterior a notBefore".
            DateTime notBefore = now.AddSeconds(-1);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.UniqueName, user.Username),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new("username", user.Username)
            };

            foreach (string role in user.Roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _settings.Issuer,
                audience: _settings.Audience,
                claims: claims,
                notBefore: notBefore,
                expires: expires,
                signingCredentials: credentials);

            return (_handler.WriteToken(token), expires);
        }

        public string GenerateRefreshToken()
        {
            byte[] randomBytes = RandomNumberGenerator.GetBytes(64);
            return Convert.ToBase64String(randomBytes);
        }

        public ClaimsPrincipal? ValidateAccessToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token) || !_handler.CanReadToken(token))
                return null;

            try
            {
                ClaimsPrincipal principal = _handler.ValidateToken(token, GetValidationParameters(), out _);
                return principal;
            }
            catch (Exception)
            {
                // Firma inválida, token expirado, issuer/audience incorrectos, etc.
                return null;
            }
        }

        public TokenValidationParameters GetValidationParameters() => new()
        {
            ValidateIssuer = true,
            ValidIssuer = _settings.Issuer,
            ValidateAudience = true,
            ValidAudience = _settings.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _signingKey,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(_settings.ClockSkewSeconds)
        };
    }
}
