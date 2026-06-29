using JwtAuth.Stores;

namespace JwtAuthApi.Services
{
    /// <summary>
    /// Servicio en segundo plano que purga periódicamente los refresh tokens
    /// expirados del almacén, evitando que crezca sin límite. La cadencia es
    /// holgada (una vez por hora) porque la limpieza no es urgente.
    /// </summary>
    public class RefreshTokenCleanupService : BackgroundService
    {
        private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

        private readonly IRefreshTokenStore _store;
        private readonly ILogger<RefreshTokenCleanupService> _logger;

        public RefreshTokenCleanupService(
            IRefreshTokenStore store,
            ILogger<RefreshTokenCleanupService> logger)
        {
            _store = store;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var timer = new PeriodicTimer(Interval);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    int removed = _store.RemoveExpired();
                    if (removed > 0)
                        _logger.LogInformation("Refresh tokens expirados purgados: {Count}.", removed);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error al purgar refresh tokens expirados.");
                }

                try
                {
                    await timer.WaitForNextTickAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break; // apagado normal de la aplicación
                }
            }
        }
    }
}
