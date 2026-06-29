using System.Net;
using JwtAuthImpl.Auth;
using JwtAuthImpl.Products;
using JwtAuthImplTest.Helpers;

namespace JwtAuthImplTest
{
    [TestFixture]
    public class ProductsApiClientTests
    {
        private const string ProductsJson =
            "{\"message\":\"ok\",\"items\":[\"Teclado\",\"Mouse\"]}";

        // Construye el cliente de productos sobre el canal compartido
        // (ApiHttpClient), usando AuthApiClient como refresher real para poder
        // ejercitar el flujo de refresco ante 401.
        private static (ProductsApiClient client, InMemoryTokenStore store) Build(
            FakeHttpMessageHandler handler)
        {
            var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/") };
            var store = new InMemoryTokenStore();
            var refresher = new AuthApiClient(http, store, new RefreshCoordinator());
            var apiHttp = new ApiHttpClient(http, store, refresher);
            return (new ProductsApiClient(apiHttp), store);
        }

        private static string Path(HttpRequestMessage req) => req.RequestUri!.AbsolutePath;

        [Test]
        public async Task GetPublicProductsAsync_NoDeberiaAdjuntarToken()
        {
            HttpRequestMessage? captured = null;
            var handler = new FakeHttpMessageHandler(req =>
            {
                captured = req;
                return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ProductsJson);
            });
            var (client, store) = Build(handler);
            // Aunque haya un token guardado, la llamada pública no debe adjuntarlo.
            store.AccessToken = "token-xyz";

            var result = await client.GetPublicProductsAsync();

            Assert.That(result, Is.Not.Null);
            Assert.That(result!.Items, Is.EquivalentTo(new[] { "Teclado", "Mouse" }));
            Assert.That(Path(captured!), Is.EqualTo("/api/products/public"));
            Assert.That(captured!.Headers.Authorization, Is.Null);
        }

        [Test]
        public async Task GetProductsAsync_DeberiaAdjuntarBearer()
        {
            HttpRequestMessage? captured = null;
            var handler = new FakeHttpMessageHandler(req =>
            {
                captured = req;
                return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ProductsJson);
            });
            var (client, store) = Build(handler);
            store.AccessToken = "token-xyz";

            var result = await client.GetProductsAsync();

            Assert.That(result, Is.Not.Null);
            Assert.That(captured!.Headers.Authorization?.Scheme, Is.EqualTo("Bearer"));
            Assert.That(captured.Headers.Authorization?.Parameter, Is.EqualTo("token-xyz"));
        }

        [Test]
        public async Task GetProductsAsync_DeberiaRefrescarYReintentar_Ante401()
        {
            var handler = new FakeHttpMessageHandler(req =>
            {
                switch (Path(req))
                {
                    case "/api/auth/refresh":
                        return FakeHttpMessageHandler.Json(HttpStatusCode.OK,
                            "{\"accessToken\":\"nuevo\",\"refreshToken\":\"r2\"}");
                    case "/api/products":
                        // Con el token viejo responde 401; con el nuevo, 200.
                        return req.Headers.Authorization?.Parameter == "nuevo"
                            ? FakeHttpMessageHandler.Json(HttpStatusCode.OK, ProductsJson)
                            : FakeHttpMessageHandler.Empty(HttpStatusCode.Unauthorized);
                    default:
                        return FakeHttpMessageHandler.Empty(HttpStatusCode.NotFound);
                }
            });
            var (client, store) = Build(handler);
            store.AccessToken = "viejo";
            store.RefreshToken = "r1";

            var result = await client.GetProductsAsync();

            Assert.That(result, Is.Not.Null, "tras refrescar debería obtener el listado");
            Assert.That(store.AccessToken, Is.EqualTo("nuevo"), "el token debió rotarse");
        }

        [Test]
        public async Task GetProductsAsync_DeberiaRetornarNull_SiElRefreshFalla()
        {
            var handler = new FakeHttpMessageHandler(req =>
                FakeHttpMessageHandler.Empty(HttpStatusCode.Unauthorized));
            var (client, store) = Build(handler);
            store.AccessToken = "viejo";
            store.RefreshToken = "r1";

            var result = await client.GetProductsAsync();

            Assert.That(result, Is.Null);
        }

        [Test]
        public async Task CreateProductAsync_DeberiaDevolverElCodigoHttp()
        {
            var handler = new FakeHttpMessageHandler(req =>
                FakeHttpMessageHandler.Empty(HttpStatusCode.Created));
            var (client, store) = Build(handler);
            store.AccessToken = "token";

            HttpStatusCode status = await client.CreateProductAsync("Tablet");

            Assert.That(status, Is.EqualTo(HttpStatusCode.Created));
        }
    }
}
