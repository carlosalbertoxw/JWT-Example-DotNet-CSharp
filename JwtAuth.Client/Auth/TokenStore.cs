using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace JwtAuth.Client.Auth
{
    /// <summary>
    /// Persiste el access token y el refresh token en el almacenamiento de
    /// sesión del navegador mediante <see cref="ProtectedSessionStorage"/> (los
    /// datos se cifran del lado del servidor con la Data Protection API).
    /// </summary>
    /// <remarks>
    /// sessionStorage es por pestaña: cada pestaña tiene su propia sesión y su
    /// propia familia de refresh tokens. Con localStorage las pestañas
    /// compartirían el refresh token, pero cada circuito de Blazor serializa sus
    /// refrescos por separado: dos pestañas que renovaran a la vez canjearían el
    /// mismo token, la API lo vería como un reuso y revocaría todas las sesiones
    /// del usuario. Además, el valor de sessionStorage desaparece al cerrar la
    /// pestaña. El costo: hay que iniciar sesión en cada pestaña nueva.
    /// </remarks>
    public class TokenStore : ITokenStore
    {
        private const string AccessKey = "jwt.accessToken";
        private const string RefreshKey = "jwt.refreshToken";

        private readonly ProtectedSessionStorage _storage;

        public TokenStore(ProtectedSessionStorage storage)
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
