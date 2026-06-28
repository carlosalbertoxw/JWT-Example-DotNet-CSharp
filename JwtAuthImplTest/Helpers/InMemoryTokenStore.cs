using JwtAuthImpl.Auth;

namespace JwtAuthImplTest.Helpers
{
    /// <summary>
    /// Implementación de <see cref="ITokenStore"/> en memoria para pruebas,
    /// sin dependencia de ProtectedLocalStorage / JS interop.
    /// </summary>
    public class InMemoryTokenStore : ITokenStore
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }

        public Task SaveAsync(string accessToken, string refreshToken)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            return Task.CompletedTask;
        }

        public Task<string?> GetAccessTokenAsync() => Task.FromResult(AccessToken);

        public Task<string?> GetRefreshTokenAsync() => Task.FromResult(RefreshToken);

        public Task ClearAsync()
        {
            AccessToken = null;
            RefreshToken = null;
            return Task.CompletedTask;
        }
    }
}
