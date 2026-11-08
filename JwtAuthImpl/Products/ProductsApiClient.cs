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

        /// <summary>Obtiene el catálogo público, sin precio (no requiere autenticación).</summary>
        public async Task<IReadOnlyList<PublicProduct>?> GetPublicProductsAsync()
        {
            HttpResponseMessage response = await _api.SendAsync(
                () => new HttpRequestMessage(HttpMethod.Get, "api/products/public"));

            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<List<PublicProduct>>(ApiJson.Options)
                : null;
        }

        /// <summary>Obtiene el catálogo completo con precio (requiere autenticación).</summary>
        public async Task<IReadOnlyList<Product>?> GetProductsAsync()
        {
            HttpResponseMessage response = await _api.SendAuthorizedAsync(
                () => new HttpRequestMessage(HttpMethod.Get, "api/products"));

            return response.IsSuccessStatusCode
                ? await response.Content.ReadFromJsonAsync<List<Product>>(ApiJson.Options)
                : null;
        }

        /// <summary>Crea un producto (requiere rol Admin). Devuelve el código HTTP.</summary>
        public async Task<HttpStatusCode> CreateProductAsync(NewProduct product)
        {
            HttpResponseMessage response = await _api.SendAuthorizedAsync(() =>
                new HttpRequestMessage(HttpMethod.Post, "api/products")
                {
                    Content = JsonContent.Create(product, options: ApiJson.Options)
                });

            return response.StatusCode;
        }
    }
}
