using JwtAuth.Stores;

namespace JwtAuth.Security
{
    /// <summary>
    /// Límite de intentos con ventana deslizante (protección anti fuerza bruta).
    /// Solo se registran los intentos FALLIDOS: tras <c>maxAttempts</c> fallos
    /// dentro de la ventana, la clave queda bloqueada hasta que el fallo más
    /// antiguo salga de ella. La clave agrupa los intentos, p. ej.
    /// <c>login:user:&lt;usuario&gt;</c> o <c>login:ip:&lt;ip&gt;</c>.
    /// </summary>
    public class RateLimiter
    {
        private readonly IAttemptStore _attempts;
        private readonly int _maxAttempts;
        private readonly TimeSpan _window;
        private readonly TimeProvider _time;

        public RateLimiter(IAttemptStore attempts, int maxAttempts, TimeSpan window, TimeProvider time)
        {
            _attempts = attempts;
            _maxAttempts = maxAttempts;
            _window = window;
            _time = time;
        }

        public bool TooManyAttempts(string key) =>
            _attempts.CountSince(key, WindowStart()) >= _maxAttempts;

        /// <summary>Segundos que faltan para poder reintentar (para el header Retry-After).</summary>
        public int RetryAfterSeconds(string key)
        {
            DateTimeOffset? oldest = _attempts.OldestSince(key, WindowStart());
            if (oldest is null)
                return 0;
            return Math.Max(0, (int)Math.Ceiling((oldest.Value + _window - _time.GetUtcNow()).TotalSeconds));
        }

        public void RecordFailure(string key)
        {
            _attempts.Add(key, _time.GetUtcNow());
            // Mantenimiento oportunista: descartar intentos fuera de la ventana.
            _attempts.PurgeBefore(WindowStart());
        }

        public void Clear(string key) => _attempts.DeleteKey(key);

        private DateTimeOffset WindowStart() => _time.GetUtcNow() - _window;
    }
}
