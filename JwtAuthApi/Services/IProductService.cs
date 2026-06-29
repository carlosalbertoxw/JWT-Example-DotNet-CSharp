namespace JwtAuthApi.Services
{
    /// <summary>
    /// Lógica de negocio del catálogo de productos. Es contenido de ejemplo,
    /// independiente del sistema de autenticación JWT; se apoya en la capa de
    /// datos para leer y persistir el catálogo.
    /// </summary>
    public interface IProductService
    {
        /// <summary>Devuelve el catálogo completo de productos.</summary>
        IReadOnlyList<string> GetCatalog();

        /// <summary>Agrega un producto al catálogo.</summary>
        void Create(string name);
    }
}
