using System.ComponentModel.DataAnnotations;

namespace JwtAuthApi.Contracts
{
    /// <summary>Credenciales enviadas al endpoint de inicio de sesión.</summary>
    public record LoginRequest
    {
        [Required]
        public string Username { get; init; } = string.Empty;

        [Required]
        public string Password { get; init; } = string.Empty;
    }

    /// <summary>Refresh token enviado a los endpoints de renovación y logout.</summary>
    public record RefreshRequest
    {
        [Required]
        public string RefreshToken { get; init; } = string.Empty;
    }

    /// <summary>Respuesta con el par de tokens emitido tras login o refresh.</summary>
    public record AuthResponse
    {
        public string AccessToken { get; init; } = string.Empty;

        public DateTime AccessTokenExpiresAtUtc { get; init; }

        public string RefreshToken { get; init; } = string.Empty;

        public DateTime RefreshTokenExpiresAtUtc { get; init; }

        public string TokenType { get; init; } = "Bearer";
    }
}
