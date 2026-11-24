using Bunit;
using Bunit.TestDoubles;
using JwtAuth.Client.Auth;
using JwtAuth.Client.Tests.Helpers;
using Microsoft.Extensions.DependencyInjection;
using NavMenu = JwtAuth.Web.Components.Layout.NavMenu;

namespace JwtAuth.Client.Tests.Components
{
    [TestFixture]
    public class NavMenuTests
    {
        private static BunitContext CreateContext()
        {
            var ctx = new BunitContext();

            // Servicios que NavMenu inyecta. El proveedor concreto solo se usa en
            // el handler de logout (no durante el render), así que basta con que
            // se pueda construir; el estado de auth lo controla AddTestAuthorization.
            var store = new InMemoryTokenStore();
            var http = new HttpClient(new FakeHttpMessageHandler(
                req => FakeHttpMessageHandler.Empty(System.Net.HttpStatusCode.OK)))
            {
                BaseAddress = new Uri("http://localhost/")
            };
            var api = new AuthApiClient(http, store, new RefreshCoordinator());

            ctx.Services.AddSingleton(api);
            ctx.Services.AddSingleton(new JwtAuthenticationStateProvider(store, api));
            return ctx;
        }

        [Test]
        public void NavMenu_Anonimo_DeberiaMostrarIniciarSesion()
        {
            using var ctx = CreateContext();
            ctx.AddAuthorization(); // por defecto: no autenticado

            var cut = ctx.Render<NavMenu>();

            Assert.That(cut.Markup, Does.Contain("Iniciar sesión"));
            Assert.That(cut.Markup, Does.Not.Contain("Cerrar sesión"));
        }

        [Test]
        public void NavMenu_Autenticado_DeberiaMostrarUsuarioYCerrarSesion()
        {
            using var ctx = CreateContext();
            var auth = ctx.AddAuthorization();
            auth.SetAuthorized("admin");

            var cut = ctx.Render<NavMenu>();

            Assert.That(cut.Markup, Does.Contain("admin"));
            Assert.That(cut.Markup, Does.Contain("Cerrar sesión"));
            Assert.That(cut.Markup, Does.Not.Contain("Iniciar sesión"));
        }

        [Test]
        public void NavMenu_DeberiaTenerEnlaceAlCatalogoPublico()
        {
            using var ctx = CreateContext();
            ctx.AddAuthorization();

            var cut = ctx.Render<NavMenu>();

            Assert.That(cut.Markup, Does.Contain("Catálogo público"));
            Assert.That(cut.Markup, Does.Contain("href=\"catalog\""));
        }
    }
}
