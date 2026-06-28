namespace JwtAuth.Models
{
    /// <summary>
    /// Refresh token persistido del lado del servidor. Permite emitir nuevos
    /// access tokens sin volver a pedir credenciales y poder revocarlos
    /// (logout / rotación) de forma centralizada.
    /// </summary>
    public class RefreshToken
    {
        /// <summary>Valor opaco y aleatorio del token.</summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>Usuario propietario del token.</summary>
        public Guid UserId { get; set; }

        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

        public DateTime ExpiresAtUtc { get; set; }

        /// <summary>Fecha de revocación; null si sigue vigente.</summary>
        public DateTime? RevokedAtUtc { get; set; }

        /// <summary>Indica si el token aún puede utilizarse.</summary>
        public bool IsActive => RevokedAtUtc is null && DateTime.UtcNow < ExpiresAtUtc;
    }
}
