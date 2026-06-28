namespace JwtAuthImpl.Models
{
    /// <summary>Credenciales enviadas al endpoint de login de la API.</summary>
    public record LoginRequest(string Username, string Password);

    /// <summary>Refresh token enviado a los endpoints de refresh y logout.</summary>
    public record RefreshRequest(string RefreshToken);

    /// <summary>Par de tokens devuelto por la API tras login o refresh.</summary>
    public class AuthResponse
    {
        public string AccessToken { get; set; } = string.Empty;

        public DateTime AccessTokenExpiresAtUtc { get; set; }

        public string RefreshToken { get; set; } = string.Empty;

        public DateTime RefreshTokenExpiresAtUtc { get; set; }

        public string TokenType { get; set; } = "Bearer";
    }
}
