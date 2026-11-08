using System.Collections.Concurrent;
using JwtAuth.Stores;

namespace JwtAuthDatos.Stores
{
    /// <summary>Intentos fallidos de login/refresh en memoria (para el rate limiting).</summary>
    public class InMemoryAttemptStore : IAttemptStore
    {
        private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTimeOffset>> _attempts = new();

        public void Add(string key, DateTimeOffset at) =>
            _attempts.GetOrAdd(key, _ => new ConcurrentQueue<DateTimeOffset>()).Enqueue(at);

        public int CountSince(string key, DateTimeOffset since) =>
            Since(key, since).Count();

        public DateTimeOffset? OldestSince(string key, DateTimeOffset since)
        {
            DateTimeOffset[] inWindow = Since(key, since).ToArray();
            return inWindow.Length == 0 ? null : inWindow.Min();
        }

        public void DeleteKey(string key) => _attempts.TryRemove(key, out _);

        public void PurgeBefore(DateTimeOffset before)
        {
            foreach ((string key, ConcurrentQueue<DateTimeOffset> queue) in _attempts)
            {
                // La cola está ordenada por llegada: basta con quitar del frente.
                while (queue.TryPeek(out DateTimeOffset oldest) && oldest < before)
                    queue.TryDequeue(out _);

                if (queue.IsEmpty)
                    _attempts.TryRemove(key, out _);
            }
        }

        private IEnumerable<DateTimeOffset> Since(string key, DateTimeOffset since) =>
            _attempts.TryGetValue(key, out ConcurrentQueue<DateTimeOffset>? queue)
                ? queue.Where(at => at >= since)
                : [];
    }
}
