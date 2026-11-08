using System.Collections.Concurrent;
using JwtAuthDatos.Models;

namespace JwtAuthDatos.Stores
{
    /// <summary>
    /// Implementación en memoria de <see cref="IProductStore"/>. Se siembra con
    /// el catálogo de ejemplo común a todos los ejemplos JWT.
    /// </summary>
    public class InMemoryProductStore : IProductStore
    {
        private readonly ConcurrentQueue<Product> _products = new(
        [
            new Product(1, "Teclado mecánico", "Switches rojos, retroiluminado", 89.99m),
            new Product(2, "Mouse inalámbrico", "Sensor óptico de 16000 DPI", 45.50m),
            new Product(3, "Monitor 27\"", "Panel IPS, 144 Hz", 320.00m),
            new Product(4, "Dock USB-C", "HDMI doble, carga de 100 W", 129.00m)
        ]);

        private int _lastId = 4;

        public IReadOnlyList<Product> GetAll() => _products.ToArray();

        public Product Add(string name, string description, decimal price)
        {
            var product = new Product(Interlocked.Increment(ref _lastId), name, description, price);
            _products.Enqueue(product);
            return product;
        }
    }
}
