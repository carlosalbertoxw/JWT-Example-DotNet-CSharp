using System.Net;
using Bunit;
using Bunit.TestDoubles;
using JwtAuth.Client.Auth;
using JwtAuth.Client.Products;
using JwtAuth.Client.Tests.Helpers;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using ProductsPage = JwtAuth.Web.Components.Pages.Products;

namespace JwtAuth.Client.Tests.Components
{
    [TestFixture]
    public class ProductsTests
    {
        private const string ProductsJson =
            "[{\"id\":1,\"name\":\"Teclado\",\"description\":\"Rojo\",\"price\":89.99}," +
            "{\"id\":2,\"name\":\"Mouse\",\"description\":\"Óptico\",\"price\":45.5}]";

        private static BunitContext CreateContext()
        {
            var ctx = new BunitContext();
            var store = new InMemoryTokenStore();
            var http = new HttpClient(new FakeHttpMessageHandler(
                req => FakeHttpMessageHandler.Json(HttpStatusCode.OK, ProductsJson)))
            {
                BaseAddress = new Uri("http://localhost/")
            };
            var refresher = new AuthApiClient(http, store, new RefreshCoordinator());
            var apiHttp = new ApiHttpClient(http, store, refresher);
            ctx.Services.AddSingleton(new ProductsApiClient(apiHttp));
            return ctx;
        }

        [Test]
        public void Products_Anonimo_DeberiaRedirigirAlLogin()
        {
            using var ctx = CreateContext();
            ctx.AddAuthorization(); // no autenticado

            ctx.Render<ProductsPage>();

            var nav = ctx.Services.GetRequiredService<NavigationManager>();
            Assert.That(nav.Uri, Does.EndWith("login?returnUrl=products"));
        }

        [Test]
        public void Products_Admin_DeberiaMostrarProductosYSeccionCrear()
        {
            using var ctx = CreateContext();
            var auth = ctx.AddAuthorization();
            auth.SetAuthorized("admin");
            auth.SetRoles("Admin");

            var cut = ctx.Render<ProductsPage>();

            Assert.That(cut.Markup, Does.Contain("Teclado"));
            Assert.That(cut.Markup, Does.Contain("$89.99"), "el listado autenticado muestra el precio");
            Assert.That(cut.Markup, Does.Contain("Crear producto (solo Admin)"));
        }

        [Test]
        public void Products_Usuario_NoDeberiaMostrarSeccionCrear()
        {
            using var ctx = CreateContext();
            var auth = ctx.AddAuthorization();
            auth.SetAuthorized("user");
            auth.SetRoles("User");

            var cut = ctx.Render<ProductsPage>();

            Assert.That(cut.Markup, Does.Contain("Teclado"));
            Assert.That(cut.Markup, Does.Not.Contain("Crear producto (solo Admin)"));
            Assert.That(cut.Markup, Does.Contain("Inicia sesión como"));
        }
    }
}
