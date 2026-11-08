using System.Net;
using Bunit;
using JwtAuthImpl.Auth;
using JwtAuthImplTest.Helpers;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Login = JwtAuthImplFront.Components.Pages.Login;

namespace JwtAuthImplTest.Components
{
    [TestFixture]
    public class LoginTests
    {
        private static BunitContext CreateContext(HttpStatusCode loginStatus)
        {
            var ctx = new BunitContext();
            var store = new InMemoryTokenStore();

            string loginJson =
                $"{{\"access_token\":\"{TestJwt.Create("admin", "Admin")}\",\"refresh_token\":\"r1\"}}";

            var http = new HttpClient(new FakeHttpMessageHandler(req =>
                loginStatus == HttpStatusCode.OK
                    ? FakeHttpMessageHandler.Json(HttpStatusCode.OK, loginJson)
                    : FakeHttpMessageHandler.Empty(loginStatus)))
            {
                BaseAddress = new Uri("http://localhost/")
            };

            var api = new AuthApiClient(http, store, new RefreshCoordinator());
            ctx.Services.AddSingleton(api);
            ctx.Services.AddSingleton(new JwtAuthenticationStateProvider(store, api));
            return ctx;
        }

        private static void Submit(IRenderedComponent<Login> cut, string password)
        {
            cut.Find("input[autocomplete=username]").Change("admin");
            cut.Find("input[autocomplete=current-password]").Change(password);
            cut.Find("form").Submit();
        }

        [Test]
        public void Login_ConCredencialesValidas_DeberiaNavegarAProductos()
        {
            using var ctx = CreateContext(HttpStatusCode.OK);
            var cut = ctx.Render<Login>();

            Submit(cut, "Admin123!");

            var nav = ctx.Services.GetRequiredService<NavigationManager>();
            cut.WaitForAssertion(
                () => Assert.That(nav.Uri, Does.EndWith("products")),
                TimeSpan.FromSeconds(2));
        }

        [Test]
        public void Login_ConReturnUrlExterno_NoDeberiaSalirDelSitio()
        {
            using var ctx = CreateContext(HttpStatusCode.OK);
            var nav = ctx.Services.GetRequiredService<NavigationManager>();
            nav.NavigateTo("login?returnUrl=https://sitio-falso.example");
            var cut = ctx.Render<Login>();

            Submit(cut, "Admin123!");

            cut.WaitForAssertion(
                () => Assert.That(nav.Uri, Is.EqualTo("http://localhost/products")),
                TimeSpan.FromSeconds(2));
        }

        [TestCase(null, "products")]
        [TestCase("products", "products")]
        [TestCase("https://sitio-falso.example", "products")]
        [TestCase("//sitio-falso.example", "products")]
        [TestCase("\\\\sitio-falso.example", "products")]
        [TestCase("javascript:alert(1)", "products")]
        public void SafeReturnUrl_SoloAceptaRutasLocales(string? returnUrl, string expected)
        {
            Assert.That(Login.SafeReturnUrl(returnUrl), Is.EqualTo(expected));
        }

        [Test]
        public void Login_ConCredencialesInvalidas_DeberiaMostrarError()
        {
            using var ctx = CreateContext(HttpStatusCode.Unauthorized);
            var cut = ctx.Render<Login>();

            Submit(cut, "mala");

            cut.WaitForAssertion(
                () => Assert.That(cut.Markup, Does.Contain("Usuario o contraseña inválidos")),
                TimeSpan.FromSeconds(2));

            var nav = ctx.Services.GetRequiredService<NavigationManager>();
            Assert.That(nav.Uri, Does.Not.EndWith("products"));
        }
    }
}
