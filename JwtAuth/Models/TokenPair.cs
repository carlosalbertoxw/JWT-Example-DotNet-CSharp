namespace JwtAuth.Models
{
    /// <summary>
    /// Resultado de un inicio de sesión o de una renovación: el access token
    /// de corta duración junto con el refresh token de larga duración.
    /// </summary>
    public class TokenPair
    {
        public string AccessToken { get; init; } = string.Empty;

        public string RefreshToken { get; init; } = string.Empty;

        /// <summary>Segundos de vida del access token.</summary>
        public int ExpiresInSeconds { get; init; }
    }
}
