namespace JwtAuthImpl.Models
{
    /// <summary>Producto del catálogo público (la API no envía el precio).</summary>
    public record PublicProduct(int Id, string Name, string Description);

    /// <summary>Producto del catálogo completo (requiere sesión).</summary>
    public record Product(int Id, string Name, string Description, decimal Price);

    /// <summary>Datos para crear un producto (requiere rol Admin).</summary>
    public record NewProduct(string Name, string Description, decimal Price);
}
