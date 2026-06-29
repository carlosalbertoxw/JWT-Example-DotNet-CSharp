using System.Net.Http.Headers;
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
                "api/auth/login", new LoginRequest(username, password));

            if (!response.IsSuccessStatusCode)
                return false;

            var auth = await response.Content.ReadFromJsonAsync<AuthResponse>();
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
                    "api/auth/refresh", new RefreshRequest(current));

                if (!response.IsSuccessStatusCode)
                    return false;

                var auth = await response.Content.ReadFromJsonAsync<AuthResponse>();
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

        /// <summary>Revoca el refresh token en la API y limpia el almacenamiento local.</summary>
        public async Task LogoutAsync()
        {
            string? refreshToken = await _tokenStore.GetRefreshTokenAsync();

            if (!string.IsNullOrEmpty(refreshToken))
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, "api/auth/logout")
                    {
                        Content = JsonContent.Create(new RefreshRequest(refreshToken))
                    };

                    string? accessToken = await _tokenStore.GetAccessTokenAsync();
                    if (!string.IsNullOrEmpty(accessToken))
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                    await _http.SendAsync(request);
                }
                catch
                {
                    // El logout local debe ocurrir aunque la llamada remota falle.
                }
            }

            await _tokenStore.ClearAsync();
        }
    }
}
