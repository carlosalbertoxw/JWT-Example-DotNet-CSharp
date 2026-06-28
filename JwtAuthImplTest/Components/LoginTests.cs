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
        private static Bunit.TestContext CreateContext(HttpStatusCode loginStatus)
        {
            var ctx = new Bunit.TestContext();
            var store = new InMemoryTokenStore();

            string loginJson =
                $"{{\"accessToken\":\"{TestJwt.Create("admin", new[] { "Admin" })}\",\"refreshToken\":\"r1\"}}";

            var http = new HttpClient(new FakeHttpMessageHandler(req =>
                loginStatus == HttpStatusCode.OK
                    ? FakeHttpMessageHandler.Json(HttpStatusCode.OK, loginJson)
                    : FakeHttpMessageHandler.Empty(loginStatus)))
            {
                BaseAddress = new Uri("http://localhost/")
            };

            var api = new AuthApiClient(http, store);
            ctx.Services.AddSingleton(api);
            ctx.Services.AddSingleton(new JwtAuthenticationStateProvider(store, api));
            return ctx;
        }

        [Test]
        public void Login_ConCredencialesValidas_DeberiaNavegarAProductos()
        {
            using var ctx = CreateContext(HttpStatusCode.OK);
            var cut = ctx.RenderComponent<Login>();

            cut.Find("input[autocomplete=username]").Change("admin");
            cut.Find("input[autocomplete=current-password]").Change("Admin123!");
            cut.Find("form").Submit();

            var nav = ctx.Services.GetRequiredService<NavigationManager>();
            cut.WaitForAssertion(
                () => Assert.That(nav.Uri, Does.EndWith("products")),
                TimeSpan.FromSeconds(2));
        }

        [Test]
        public void Login_ConCredencialesInvalidas_DeberiaMostrarError()
        {
            using var ctx = CreateContext(HttpStatusCode.Unauthorized);
            var cut = ctx.RenderComponent<Login>();

            cut.Find("input[autocomplete=username]").Change("admin");
            cut.Find("input[autocomplete=current-password]").Change("mala");
            cut.Find("form").Submit();

            cut.WaitForAssertion(
                () => Assert.That(cut.Markup, Does.Contain("Usuario o contraseña inválidos")),
                TimeSpan.FromSeconds(2));

            var nav = ctx.Services.GetRequiredService<NavigationManager>();
            Assert.That(nav.Uri, Does.Not.EndWith("products"));
        }
    }
}
