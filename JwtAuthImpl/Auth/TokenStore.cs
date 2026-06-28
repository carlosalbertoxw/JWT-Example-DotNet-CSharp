using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Persiste el access token y el refresh token en el almacenamiento local
    /// del navegador mediante <see cref="ProtectedLocalStorage"/> (los datos se
    /// cifran del lado del servidor con la Data Protection API).
    /// </summary>
    public class TokenStore : ITokenStore
    {
        private const string AccessKey = "jwt.accessToken";
        private const string RefreshKey = "jwt.refreshToken";

        private readonly ProtectedLocalStorage _storage;

        public TokenStore(ProtectedLocalStorage storage)
        {
            _storage = storage;
        }

        public async Task SaveAsync(string accessToken, string refreshToken)
        {
            await _storage.SetAsync(AccessKey, accessToken);
            await _storage.SetAsync(RefreshKey, refreshToken);
        }

        public Task<string?> GetAccessTokenAsync() => ReadAsync(AccessKey);

        public Task<string?> GetRefreshTokenAsync() => ReadAsync(RefreshKey);

        public async Task ClearAsync()
        {
            await _storage.DeleteAsync(AccessKey);
            await _storage.DeleteAsync(RefreshKey);
        }

        private async Task<string?> ReadAsync(string key)
        {
            try
            {
                ProtectedBrowserStorageResult<string> result = await _storage.GetAsync<string>(key);
                return result.Success ? result.Value : null;
            }
            catch
            {
                // Puede fallar si se invoca antes de que el circuito esté listo
                // (p. ej. durante prerenderizado). Se trata como "sin token".
                return null;
            }
        }
    }
}
