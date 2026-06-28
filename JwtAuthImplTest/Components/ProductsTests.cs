using System.Net;
using Bunit;
using Bunit.TestDoubles;
using JwtAuthImpl.Auth;
using JwtAuthImplTest.Helpers;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Products = JwtAuthImplFront.Components.Pages.Products;

namespace JwtAuthImplTest.Components
{
    [TestFixture]
    public class ProductsTests
    {
        private const string ProductsJson =
            "{\"message\":\"Hola\",\"items\":[\"Teclado\",\"Mouse\"]}";

        private static Bunit.TestContext CreateContext()
        {
            var ctx = new Bunit.TestContext();
            var store = new InMemoryTokenStore();
            var http = new HttpClient(new FakeHttpMessageHandler(
                req => FakeHttpMessageHandler.Json(HttpStatusCode.OK, ProductsJson)))
            {
                BaseAddress = new Uri("http://localhost/")
            };
            ctx.Services.AddSingleton(new AuthApiClient(http, store));
            return ctx;
        }

        [Test]
        public void Products_Anonimo_DeberiaRedirigirAlLogin()
        {
            using var ctx = CreateContext();
            ctx.AddTestAuthorization(); // no autenticado

            ctx.RenderComponent<Products>();

            var nav = ctx.Services.GetRequiredService<NavigationManager>();
            Assert.That(nav.Uri, Does.EndWith("login?returnUrl=products"));
        }

        [Test]
        public void Products_Admin_DeberiaMostrarProductosYSeccionCrear()
        {
            using var ctx = CreateContext();
            var auth = ctx.AddTestAuthorization();
            auth.SetAuthorized("admin");
            auth.SetRoles("Admin");

            var cut = ctx.RenderComponent<Products>();

            Assert.That(cut.Markup, Does.Contain("Teclado"));
            Assert.That(cut.Markup, Does.Contain("Crear producto (solo Admin)"));
        }

        [Test]
        public void Products_Usuario_NoDeberiaMostrarSeccionCrear()
        {
            using var ctx = CreateContext();
            var auth = ctx.AddTestAuthorization();
            auth.SetAuthorized("user");
            auth.SetRoles("User");

            var cut = ctx.RenderComponent<Products>();

            Assert.That(cut.Markup, Does.Contain("Teclado"));
            Assert.That(cut.Markup, Does.Not.Contain("Crear producto (solo Admin)"));
            Assert.That(cut.Markup, Does.Contain("Inicia sesión como"));
        }
    }
}
