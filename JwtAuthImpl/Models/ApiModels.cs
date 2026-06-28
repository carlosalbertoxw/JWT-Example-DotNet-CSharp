namespace JwtAuthImpl.Models
{
    /// <summary>Respuesta de los endpoints de productos de la API.</summary>
    public class ProductsResponse
    {
        public string Message { get; set; } = string.Empty;

        public string[] Items { get; set; } = Array.Empty<string>();
    }

    /// <summary>Respuesta del endpoint /api/auth/me con los claims del usuario.</summary>
    public class MeResponse
    {
        public string? UserId { get; set; }

        public string? Username { get; set; }

        public string[] Roles { get; set; } = Array.Empty<string>();
    }
}
