using System.Net;
using JwtAuthImpl.Auth;
using JwtAuthImplTest.Helpers;

namespace JwtAuthImplTest
{
    [TestFixture]
    public class AuthApiClientTests
    {
        private const string LoginJson =
            "{\"accessToken\":\"a1\",\"refreshToken\":\"r1\",\"tokenType\":\"Bearer\"}";

        private const string ProductsJson =
            "{\"message\":\"ok\",\"items\":[\"Teclado\",\"Mouse\"]}";

        private static (AuthApiClient client, InMemoryTokenStore store) Build(
            FakeHttpMessageHandler handler)
        {
            var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/") };
            var store = new InMemoryTokenStore();
            return (new AuthApiClient(http, store), store);
        }

        private static string Path(HttpRequestMessage req) => req.RequestUri!.AbsolutePath;

        [Test]
        public async Task LoginAsync_DeberiaGuardarTokens_EnExito()
        {
            var handler = new FakeHttpMessageHandler(req =>
                FakeHttpMessageHandler.Json(HttpStatusCode.OK, LoginJson));
            var (client, store) = Build(handler);

            bool ok = await client.LoginAsync("admin", "Admin123!");

            Assert.That(ok, Is.True);
            Assert.That(store.AccessToken, Is.EqualTo("a1"));
            Assert.That(store.RefreshToken, Is.EqualTo("r1"));
        }

        [Test]
        public async Task LoginAsync_DeberiaFallar_Con401()
        {
            var handler = new FakeHttpMessageHandler(req =>
                FakeHttpMessageHandler.Empty(HttpStatusCode.Unauthorized));
            var (client, store) = Build(handler);

            bool ok = await client.LoginAsync("admin", "mala");

            Assert.That(ok, Is.False);
            Assert.That(store.AccessToken, Is.Null);
        }

        [Test]
        public async Task GetPublicProductsAsync_NoDeberiaAdjuntarToken()
        {
            HttpRequestMessage? captured = null;
            var handler = new FakeHttpMessageHandler(req =>
            {
                captured = req;
                return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ProductsJson);
            });
            var (client, _) = Build(handler);

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
                Path(req) == "/api/auth/refresh"
                    ? FakeHttpMessageHandler.Empty(HttpStatusCode.Unauthorized)
                    : FakeHttpMessageHandler.Empty(HttpStatusCode.Unauthorized));
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

        [Test]
        public async Task LogoutAsync_DeberiaLimpiarElStore_AunqueLaApiFalle()
        {
            var handler = new FakeHttpMessageHandler(req =>
                FakeHttpMessageHandler.Empty(HttpStatusCode.InternalServerError));
            var (client, store) = Build(handler);
            store.AccessToken = "a1";
            store.RefreshToken = "r1";

            await client.LogoutAsync();

            Assert.That(store.AccessToken, Is.Null);
            Assert.That(store.RefreshToken, Is.Null);
        }
    }
}
