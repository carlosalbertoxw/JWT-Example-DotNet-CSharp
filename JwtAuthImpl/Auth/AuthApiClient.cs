using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using JwtAuthImpl.Models;

namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Cliente tipado que encapsula las llamadas a la JwtAuthApi: autenticación
    /// (login, refresh, logout) y consumo de endpoints protegidos. Adjunta el
    /// access token automáticamente e intenta refrescarlo una vez si la API
    /// responde 401.
    /// </summary>
    public class AuthApiClient
    {
        private readonly HttpClient _http;
        private readonly ITokenStore _tokenStore;

        public AuthApiClient(HttpClient http, ITokenStore tokenStore)
        {
            _http = http;
            _tokenStore = tokenStore;
        }

        // ----- Autenticación -----

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

        /// <summary>Renueva el par de tokens usando el refresh token almacenado.</summary>
        public async Task<bool> TryRefreshAsync()
        {
            string? refreshToken = await _tokenStore.GetRefreshTokenAsync();
            if (string.IsNullOrEmpty(refreshToken))
                return false;

            HttpResponseMessage response = await _http.PostAsJsonAsync(
                "api/auth/refresh", new RefreshRequest(refreshToken));

            if (!response.IsSuccessStatusCode)
                return false;

            var auth = await response.Content.ReadFromJsonAsync<AuthResponse>();
            if (auth is null)
                return false;

            await _tokenStore.SaveAsync(auth.AccessToken, auth.RefreshToken);
            return true;
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
                    await AttachTokenAsync(request);
                    await _http.SendAsync(request);
                }
                catch
                {
                    // El logout local debe ocurrir aunque la llamada remota falle.
                }
            }

            await _tokenStore.ClearAsync();
        }

        // ----- Endpoints de ejemplo -----

        /// <summary>Obtiene el catálogo público (no requiere autenticación).</summary>
        public async Task<ProductsResponse?> GetPublicProductsAsync()
        {
            // Llamada anónima: no se adjunta token.
            return await _http.GetFromJsonAsync<ProductsResponse>("api/products/public");
        }

        /// <summary>Obtiene el listado de productos (requiere autenticación).</summary>
        public async Task<ProductsResponse?> GetProductsAsync()
        {
            HttpResponseMessage response = await SendAuthorizedAsync(
                () => new HttpRequestMessage(HttpMethod.Get, "api/products"));

            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<ProductsResponse>()
                : null;
        }

        /// <summary>Crea un producto (requiere rol Admin). Devuelve el código HTTP.</summary>
        public async Task<HttpStatusCode> CreateProductAsync(string name)
        {
            HttpResponseMessage response = await SendAuthorizedAsync(() =>
                new HttpRequestMessage(HttpMethod.Post, "api/products")
                {
                    Content = JsonContent.Create(name)
                });

            return response.StatusCode;
        }

        // ----- Infraestructura -----

        /// <summary>
        /// Envía una petición autenticada. Si la API responde 401, intenta
        /// refrescar el token una vez y reintenta la petición original.
        /// </summary>
        private async Task<HttpResponseMessage> SendAuthorizedAsync(Func<HttpRequestMessage> requestFactory)
        {
            HttpRequestMessage request = requestFactory();
            await AttachTokenAsync(request);

            HttpResponseMessage response = await _http.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.Unauthorized && await TryRefreshAsync())
            {
                HttpRequestMessage retry = requestFactory();
                await AttachTokenAsync(retry);
                response = await _http.SendAsync(retry);
            }

            return response;
        }

        private async Task AttachTokenAsync(HttpRequestMessage request)
        {
            string? accessToken = await _tokenStore.GetAccessTokenAsync();
            if (!string.IsNullOrEmpty(accessToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }
    }
}
