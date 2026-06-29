namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Coordina el refresco de tokens dentro de un mismo circuito de Blazor.
    /// Se registra con ámbito (scoped), de modo que todas las llamadas del mismo
    /// usuario comparten el semáforo aunque <see cref="AuthApiClient"/> sea
    /// transitorio. Así varias peticiones que reciben 401 a la vez no disparan
    /// múltiples refrescos en paralelo (que, con la rotación del servidor, se
    /// invalidarían entre sí).
    /// </summary>
    public sealed class RefreshCoordinator : IDisposable
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public void Dispose() => Gate.Dispose();
    }
}
