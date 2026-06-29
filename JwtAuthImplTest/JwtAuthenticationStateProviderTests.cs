using System.Net;
using Microsoft.AspNetCore.Components.Authorization;
using JwtAuthImpl.Auth;
using JwtAuthImplTest.Helpers;

namespace JwtAuthImplTest
{
    [TestFixture]
    public class JwtAuthenticationStateProviderTests
    {
        private static (JwtAuthenticationStateProvider provider, InMemoryTokenStore store) Build(
            FakeHttpMessageHandler handler)
        {
            var store = new InMemoryTokenStore();
            var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost/") };
            var api = new AuthApiClient(http, store, new RefreshCoordinator());
            return (new JwtAuthenticationStateProvider(store, api), store);
        }

        private static FakeHttpMessageHandler NotUsed() =>
            new(req => FakeHttpMessageHandler.Empty(HttpStatusCode.NotFound));

        [Test]
        public async Task GetAuthenticationStateAsync_DeberiaSerAnonimo_SinToken()
        {
            var (provider, _) = Build(NotUsed());

            AuthenticationState state = await provider.GetAuthenticationStateAsync();

            Assert.That(state.User.Identity?.IsAuthenticated, Is.False);
        }

        [Test]
        public async Task GetAuthenticationStateAsync_DeberiaConstruirPrincipal_ConTokenValido()
        {
            var (provider, store) = Build(NotUsed());
            store.AccessToken = TestJwt.Create("carlos", new[] { "Admin", "User" });

            AuthenticationState state = await provider.GetAuthenticationStateAsync();

            Assert.That(state.User.Identity?.IsAuthenticated, Is.True);
            Assert.That(state.User.Identity?.Name, Is.EqualTo("carlos"));
            Assert.That(state.User.IsInRole("Admin"), Is.True);
            Assert.That(state.User.IsInRole("User"), Is.True);
        }

        [Test]
        public async Task GetAuthenticationStateAsync_DeberiaRefrescar_SiElTokenExpiro()
        {
            var handler = new FakeHttpMessageHandler(req =>
                req.RequestUri!.AbsolutePath == "/api/auth/refresh"
                    ? FakeHttpMessageHandler.Json(HttpStatusCode.OK,
                        $"{{\"accessToken\":\"{TestJwt.Create("renovado", new[] { "User" })}\",\"refreshToken\":\"r2\"}}")
                    : FakeHttpMessageHandler.Empty(HttpStatusCode.NotFound));
            var (provider, store) = Build(handler);
            store.AccessToken = TestJwt.Expired("viejo");
            store.RefreshToken = "r1";

            AuthenticationState state = await provider.GetAuthenticationStateAsync();

            Assert.That(state.User.Identity?.IsAuthenticated, Is.True);
            Assert.That(state.User.Identity?.Name, Is.EqualTo("renovado"));
        }

        [Test]
        public async Task GetAuthenticationStateAsync_DeberiaQuedarAnonimo_SiElRefreshFalla()
        {
            var handler = new FakeHttpMessageHandler(req =>
                FakeHttpMessageHandler.Empty(HttpStatusCode.Unauthorized));
            var (provider, store) = Build(handler);
            store.AccessToken = TestJwt.Expired("viejo");
            store.RefreshToken = "r1";

            AuthenticationState state = await provider.GetAuthenticationStateAsync();

            Assert.That(state.User.Identity?.IsAuthenticated, Is.False);
            Assert.That(store.AccessToken, Is.Null, "el token inválido debió limpiarse");
        }
    }
}
