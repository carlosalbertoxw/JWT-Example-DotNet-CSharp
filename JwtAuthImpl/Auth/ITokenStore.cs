namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Abstracción del almacén de tokens. Permite sustituir la implementación
    /// (p. ej. <see cref="TokenStore"/> sobre ProtectedLocalStorage) por una
    /// en memoria en las pruebas, sin depender de JS interop.
    /// </summary>
    public interface ITokenStore
    {
        Task SaveAsync(string accessToken, string refreshToken);

        Task<string?> GetAccessTokenAsync();

        Task<string?> GetRefreshTokenAsync();

        Task ClearAsync();
    }
}
