namespace JwtAuth.Models
{
    /// <summary>
    /// Refresh token persistido del lado del servidor. Permite emitir nuevos
    /// access tokens sin volver a pedir credenciales y poder revocarlos
    /// (logout / rotación) de forma centralizada. El almacén lo indexa por el
    /// hash del valor: un volcado no permite suplantar sesiones.
    /// </summary>
    public class RefreshToken
    {
        /// <summary>Usuario propietario del token.</summary>
        public Guid UserId { get; init; }

        public DateTime ExpiresAtUtc { get; init; }

        /// <summary>Fecha de revocación; null si sigue vigente.</summary>
        public DateTime? RevokedAtUtc { get; set; }

        public bool IsRevoked => RevokedAtUtc is not null;

        public bool IsExpired(DateTime nowUtc) => nowUtc >= ExpiresAtUtc;
    }
}
