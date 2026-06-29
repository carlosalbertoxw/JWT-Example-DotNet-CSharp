using JwtAuthDatos.Stores;

namespace JwtAuthApi.Services
{
    /// <summary>
    /// Implementación de <see cref="IProductService"/>. Orquesta el acceso al
    /// almacén de productos de la capa de datos. Separa la lógica de productos
    /// (contenido de ejemplo) de la lógica de autenticación.
    /// </summary>
    public class ProductService : IProductService
    {
        private readonly IProductStore _store;

        public ProductService(IProductStore store)
        {
            _store = store;
        }

        public IReadOnlyList<string> GetCatalog() => _store.GetAll();

        public void Create(string name) => _store.Add(name);
    }
}
