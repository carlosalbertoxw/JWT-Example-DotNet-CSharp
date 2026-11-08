using System.Text.Json;

namespace JwtAuthImpl.Models
{
    /// <summary>
    /// Opciones JSON del contrato común de los ejemplos JWT: la API usa
    /// snake_case (access_token, refresh_token, expires_in...).
    /// </summary>
    public static class ApiJson
    {
        public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };
    }

    /// <summary>Credenciales enviadas al endpoint de login de la API.</summary>
    public record LoginRequest(string Username, string Password);

    /// <summary>Refresh token enviado a los endpoints de refresh y logout.</summary>
    public record RefreshRequest(string RefreshToken);

    /// <summary>Par de tokens devuelto por la API tras login o refresh.</summary>
    public class AuthResponse
    {
        public string AccessToken { get; set; } = string.Empty;

        public string RefreshToken { get; set; } = string.Empty;

        public string TokenType { get; set; } = "Bearer";

        /// <summary>Segundos de vida del access token.</summary>
        public int ExpiresIn { get; set; }
    }
}
