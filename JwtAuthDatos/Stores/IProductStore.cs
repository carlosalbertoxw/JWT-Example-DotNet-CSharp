namespace JwtAuthDatos.Stores
{
    /// <summary>
    /// Almacén del catálogo de productos. Representa el origen de datos de
    /// productos; en un sistema real iría respaldado por una base de datos.
    /// </summary>
    public interface IProductStore
    {
        /// <summary>Devuelve todos los productos del catálogo.</summary>
        IReadOnlyList<string> GetAll();

        /// <summary>Agrega un producto al catálogo.</summary>
        void Add(string name);
    }
}
