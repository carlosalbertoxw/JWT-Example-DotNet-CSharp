namespace JwtAuth.Models
{
    /// <summary>
    /// Resultado de un inicio de sesión o de una renovación: el access token
    /// de corta duración junto con el refresh token de larga duración.
    /// </summary>
    public class TokenPair
    {
        public string AccessToken { get; set; } = string.Empty;

        public DateTime AccessTokenExpiresAtUtc { get; set; }

        public string RefreshToken { get; set; } = string.Empty;

        public DateTime RefreshTokenExpiresAtUtc { get; set; }
    }
}
