using System.Net;
using System.Net.Http.Json;
using JwtAuthImpl.Auth;
using JwtAuthImpl.Models;

namespace JwtAuthImpl.Products
{
    /// <summary>
    /// Cliente tipado para los endpoints de productos de la JwtAuthApi
    /// (contenido de ejemplo, ajeno a JWT). Delega en <see cref="ApiHttpClient"/>
    /// la autenticación y el reintento ante 401, por lo que esta clase solo se
    /// ocupa de los productos.
    /// </summary>
    public class ProductsApiClient
    {
        private readonly ApiHttpClient _api;

        public ProductsApiClient(ApiHttpClient api)
        {
            _api = api;
        }

        /// <summary>Obtiene el catálogo público (no requiere autenticación).</summary>
        public async Task<ProductsResponse?> GetPublicProductsAsync()
        {
            HttpResponseMessage response = await _api.SendAsync(
                () => new HttpRequestMessage(HttpMethod.Get, "api/products/public"));

            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<ProductsResponse>()
                : null;
        }

        /// <summary>Obtiene el listado de productos (requiere autenticación).</summary>
        public async Task<ProductsResponse?> GetProductsAsync()
        {
            HttpResponseMessage response = await _api.SendAuthorizedAsync(
                () => new HttpRequestMessage(HttpMethod.Get, "api/products"));

            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<ProductsResponse>()
                : null;
        }

        /// <summary>Crea un producto (requiere rol Admin). Devuelve el código HTTP.</summary>
        public async Task<HttpStatusCode> CreateProductAsync(string name)
        {
            HttpResponseMessage response = await _api.SendAuthorizedAsync(() =>
                new HttpRequestMessage(HttpMethod.Post, "api/products")
                {
                    Content = JsonContent.Create(name)
                });

            return response.StatusCode;
        }
    }
}
