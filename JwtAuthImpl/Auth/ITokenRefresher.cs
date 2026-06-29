namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Abstracción del refresco de tokens. Permite que la infraestructura HTTP
    /// (<see cref="ApiHttpClient"/>) dispare un refresco ante un 401 sin acoplarse
    /// a la implementación concreta de autenticación (<see cref="AuthApiClient"/>).
    /// </summary>
    public interface ITokenRefresher
    {
        /// <summary>
        /// Intenta renovar el par de tokens usando el refresh token almacenado.
        /// Devuelve true si el refresco tuvo éxito.
        /// </summary>
        Task<bool> TryRefreshAsync();
    }
}
