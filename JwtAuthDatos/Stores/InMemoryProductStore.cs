using System.Collections.Concurrent;

namespace JwtAuthDatos.Stores
{
    /// <summary>
    /// Implementación en memoria de <see cref="IProductStore"/>. Se siembra con
    /// un catálogo de ejemplo. En producción se reemplazaría por una
    /// persistencia real conservando el mismo contrato.
    /// </summary>
    public class InMemoryProductStore : IProductStore
    {
        // Lista concurrente para soportar lecturas y escrituras simultáneas.
        private readonly ConcurrentQueue<string> _products = new(
            new[] { "Teclado", "Mouse", "Monitor", "Webcam", "Audífonos" });

        public IReadOnlyList<string> GetAll() => _products.ToArray();

        public void Add(string name)
        {
            if (!string.IsNullOrWhiteSpace(name))
                _products.Enqueue(name);
        }
    }
}
