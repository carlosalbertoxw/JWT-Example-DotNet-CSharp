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

        private static (AuthApiClient client, InMemoryTokenStore store) Build(
            FakeHttpMessageHandler handler)
        {
            var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/") };
            var store = new InMemoryTokenStore();
            return (new AuthApiClient(http, store, new RefreshCoordinator()), store);
        }

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
