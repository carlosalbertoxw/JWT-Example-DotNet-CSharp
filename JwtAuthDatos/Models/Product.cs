namespace JwtAuthDatos.Models
{
    /// <summary>
    /// Producto del catálogo de ejemplo (contrato común de los ejemplos JWT).
    /// El precio usa <see cref="decimal"/>: con double, 0.1 + 0.2 no es exacto.
    /// </summary>
    public record Product(int Id, string Name, string Description, decimal Price);
}
