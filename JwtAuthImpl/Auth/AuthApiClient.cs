using System.Net.Http.Json;
using JwtAuthImpl.Models;

namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Cliente tipado que encapsula la autenticación contra la JwtAuthApi:
    /// login, refresco y logout. Es la única clase que conoce los endpoints
    /// <c>api/auth/*</c>; el consumo de recursos de negocio (productos) vive en
    /// clases aparte que reutilizan <see cref="ApiHttpClient"/>.
    /// </summary>
    public class AuthApiClient : ITokenRefresher
    {
        private readonly HttpClient _http;
        private readonly ITokenStore _tokenStore;
        private readonly RefreshCoordinator _refreshCoordinator;

        public AuthApiClient(HttpClient http, ITokenStore tokenStore, RefreshCoordinator refreshCoordinator)
        {
            _http = http;
            _tokenStore = tokenStore;
            _refreshCoordinator = refreshCoordinator;
        }

        /// <summary>Inicia sesión y guarda los tokens devueltos.</summary>
        public async Task<bool> LoginAsync(string username, string password)
        {
            HttpResponseMessage response = await _http.PostAsJsonAsync(
                "api/auth/login", new LoginRequest(username, password), ApiJson.Options);

            if (!response.IsSuccessStatusCode)
                return false;

            var auth = await response.Content.ReadFromJsonAsync<AuthResponse>(ApiJson.Options);
            if (auth is null)
                return false;

            await _tokenStore.SaveAsync(auth.AccessToken, auth.RefreshToken);
            return true;
        }

        /// <summary>
        /// Renueva el par de tokens usando el refresh token almacenado.
        /// Serializa el refresco con un semáforo de circuito (single-flight): si
        /// varias llamadas concurrentes lo solicitan, solo una golpea la API y
        /// las demás reutilizan su resultado, evitando rotaciones que se anularían
        /// entre sí.
        /// </summary>
        public async Task<bool> TryRefreshAsync()
        {
            string? refreshTokenBefore = await _tokenStore.GetRefreshTokenAsync();
            if (string.IsNullOrEmpty(refreshTokenBefore))
                return false;

            await _refreshCoordinator.Gate.WaitAsync();
            try
            {
                // Otra llamada pudo refrescar mientras esperábamos el semáforo: si
                // el refresh token almacenado cambió, ese refresco ya nos sirve.
                string? current = await _tokenStore.GetRefreshTokenAsync();
                if (string.IsNullOrEmpty(current))
                    return false;
                if (!string.Equals(current, refreshTokenBefore, StringComparison.Ordinal))
                    return true;

                HttpResponseMessage response = await _http.PostAsJsonAsync(
                    "api/auth/refresh", new RefreshRequest(current), ApiJson.Options);

                if (!response.IsSuccessStatusCode)
                    return false;

                var auth = await response.Content.ReadFromJsonAsync<AuthResponse>(ApiJson.Options);
                if (auth is null)
                    return false;

                await _tokenStore.SaveAsync(auth.AccessToken, auth.RefreshToken);
                return true;
            }
            finally
            {
                _refreshCoordinator.Gate.Release();
            }
        }

        /// <summary>
        /// Revoca el refresh token en la API (cierra esta sesión) y limpia el
        /// almacenamiento local. La petición no lleva access token: el refresh
        /// token es la credencial, así que no hace falta renovar nada para salir
        /// (con un access token expirado, la API respondería 401 y el refresh
        /// token seguiría vivo).
        /// </summary>
        public async Task LogoutAsync()
        {
            string? refreshToken = await _tokenStore.GetRefreshTokenAsync();

            try
            {
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    await _http.PostAsJsonAsync(
                        "api/auth/logout", new RefreshRequest(refreshToken), ApiJson.Options);
                }
            }
            catch (HttpRequestException)
            {
                // El logout local debe ocurrir aunque la llamada remota falle.
            }
            catch (TaskCanceledException)
            {
                // Timeout de la API: igual se cierra la sesión local.
            }
            finally
            {
                await _tokenStore.ClearAsync();
            }
        }
    }
}
