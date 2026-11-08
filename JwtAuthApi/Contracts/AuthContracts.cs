using System.ComponentModel.DataAnnotations;

namespace JwtAuthApi.Contracts
{
    // Contrato común de los ejemplos JWT: la API serializa en snake_case
    // (access_token, refresh_token, expires_in...), ver Program.cs.

    /// <summary>Credenciales enviadas al endpoint de inicio de sesión.</summary>
    public record LoginRequest
    {
        [Required(ErrorMessage = "username es obligatorio")]
        [MaxLength(100, ErrorMessage = "username es demasiado largo")]
        public string Username { get; init; } = string.Empty;

        [Required(ErrorMessage = "password es obligatorio")]
        [MaxLength(200, ErrorMessage = "password es demasiado largo")]
        public string Password { get; init; } = string.Empty;
    }

    /// <summary>Refresh token enviado a los endpoints de renovación y logout.</summary>
    public record RefreshRequest
    {
        [Required(ErrorMessage = "refresh_token es obligatorio")]
        [MaxLength(200, ErrorMessage = "refresh_token es demasiado largo")]
        public string RefreshToken { get; init; } = string.Empty;
    }

    /// <summary>Respuesta con el par de tokens emitido tras login o refresh.</summary>
    public record TokenResponse(string AccessToken, string RefreshToken, int ExpiresIn)
    {
        public string TokenType { get; init; } = "Bearer";
    }

    /// <summary>Respuesta de GET /api/auth/me: los claims del access token recibido.</summary>
    public record MeResponse(string? Id, string? Username, string? Role, long TokenExpiresAt);

    /// <summary>Respuesta informativa, p. ej. la del logout.</summary>
    public record MessageResponse(string Message);

    /// <summary>Formato de error del contrato común: {"error": "..."}.</summary>
    public record ErrorResponse(string Error);
}
