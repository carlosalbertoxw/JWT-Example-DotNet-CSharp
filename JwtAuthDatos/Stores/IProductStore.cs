using JwtAuthDatos.Models;

namespace JwtAuthDatos.Stores
{
    /// <summary>
    /// Almacén del catálogo de productos. Representa el origen de datos de
    /// productos; en un sistema real iría respaldado por una base de datos.
    /// </summary>
    public interface IProductStore
    {
        /// <summary>Devuelve todos los productos del catálogo.</summary>
        IReadOnlyList<Product> GetAll();

        /// <summary>Agrega un producto (el id lo asigna el almacén) y lo devuelve.</summary>
        Product Add(string name, string description, decimal price);
    }
}
