using System.Net;
using System.Net.Http.Headers;

namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Canal HTTP hacia la JwtAuthApi reutilizable por los clientes de negocio.
    /// Sabe adjuntar el access token y, ante un 401, refrescarlo una vez y
    /// reintentar la petición. Concentra aquí la plomería de autenticación para
    /// que los clientes de recursos (p. ej. productos) queden libres de ella.
    /// </summary>
    public class ApiHttpClient
    {
        private readonly HttpClient _http;
        private readonly ITokenStore _tokenStore;
        private readonly ITokenRefresher _refresher;

        public ApiHttpClient(HttpClient http, ITokenStore tokenStore, ITokenRefresher refresher)
        {
            _http = http;
            _tokenStore = tokenStore;
            _refresher = refresher;
        }

        /// <summary>Envía una petición anónima (sin adjuntar token).</summary>
        public Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> requestFactory) =>
            _http.SendAsync(requestFactory());

        /// <summary>
        /// Envía una petición autenticada. Si la API responde 401, intenta
        /// refrescar el token una vez y reintenta la petición original. La
        /// petición se reconstruye con <paramref name="requestFactory"/> porque
        /// un <see cref="HttpRequestMessage"/> no puede reenviarse dos veces.
        /// </summary>
        public async Task<HttpResponseMessage> SendAuthorizedAsync(Func<HttpRequestMessage> requestFactory)
        {
            HttpRequestMessage request = requestFactory();
            await AttachTokenAsync(request);

            HttpResponseMessage response = await _http.SendAsync(request);

            if (response.StatusCode == HttpStatusCode.Unauthorized && await _refresher.TryRefreshAsync())
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
