using System.ComponentModel.DataAnnotations;

namespace JwtAuthApi.Contracts
{
    /// <summary>Vista pública de un producto: sin precio.</summary>
    public record PublicProduct(int Id, string Name, string Description);

    /// <summary>Datos para crear un producto nuevo (solo rol Admin).</summary>
    public record CreateProductRequest
    {
        [Required(ErrorMessage = "name es obligatorio")]
        [MaxLength(100, ErrorMessage = "name no puede superar los 100 caracteres")]
        public string Name { get; init; } = string.Empty;

        [MaxLength(500, ErrorMessage = "description no puede superar los 500 caracteres")]
        public string? Description { get; init; }

        [Required(ErrorMessage = "price es obligatorio")]
        [Range(typeof(decimal), "0", "1000000000", ErrorMessage = "price debe ser un número mayor o igual a 0")]
        public decimal? Price { get; init; }
    }
}
