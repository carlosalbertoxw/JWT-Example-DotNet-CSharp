using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace JwtAuthApiTest
{
    /// <summary>
    /// Prueba de extremo a extremo de la API sobre el contrato común de los
    /// ejemplos JWT (snake_case, errores {"error": "..."}, logout público...).
    /// </summary>
    [TestFixture]
    public class ApiFlowTests
    {
        private WebApplicationFactory<Program> _factory = null!;
        private HttpClient _client = null!;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            _factory = new WebApplicationFactory<Program>();
            _client = _factory.CreateClient();
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            _client.Dispose();
            _factory.Dispose();
        }

        [Test]
        public async Task CatalogoPublico_OcultaElPrecio_YElCompletoExigeToken()
        {
            JsonElement publicList = await GetJson("/api/products/public");
            Assert.That(publicList[0].GetProperty("name").GetString(), Is.EqualTo("Teclado mecánico"));
            Assert.That(publicList.EnumerateArray().Any(p => p.TryGetProperty("price", out _)), Is.False);

            HttpResponseMessage anonymous = await _client.GetAsync("/api/products");
            Assert.That(anonymous.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That((await Json(anonymous)).TryGetProperty("error", out _), Is.True);

            JsonElement full = await GetJson("/api/products", await AccessToken("user", "User123!"));
            Assert.That(full[0].GetProperty("price").GetDecimal(), Is.EqualTo(89.99m));
        }

        [Test]
        public async Task Login_DevuelveElFormatoComun()
        {
            JsonElement tokens = await Login("admin", "Admin123!");

            Assert.That(tokens.GetProperty("access_token").GetString(), Is.Not.Empty);
            Assert.That(tokens.GetProperty("refresh_token").GetString(), Has.Length.EqualTo(64));
            Assert.That(tokens.GetProperty("token_type").GetString(), Is.EqualTo("Bearer"));
            Assert.That(tokens.GetProperty("expires_in").GetInt32(), Is.EqualTo(900));
        }

        [Test]
        public async Task Me_DevuelveLosClaimsDelToken()
        {
            JsonElement me = await GetJson("/api/auth/me", await AccessToken("admin", "Admin123!"));

            Assert.That(me.GetProperty("username").GetString(), Is.EqualTo("admin"));
            Assert.That(me.GetProperty("role").GetString(), Is.EqualTo("Admin"));
            Assert.That(me.GetProperty("token_expires_at").GetInt64(), Is.GreaterThan(0));
        }

        [Test]
        public async Task SoloAdminPuedeCrearProductos_YSeValidaLaEntrada()
        {
            var product = new { name = "Webcam HD", description = "1080p", price = 75.5m };

            HttpResponseMessage asUser = await Send(HttpMethod.Post, "/api/products", product,
                await AccessToken("user", "User123!"));
            Assert.That(asUser.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));

            string adminToken = await AccessToken("admin", "Admin123!");
            HttpResponseMessage created = await Send(HttpMethod.Post, "/api/products", product, adminToken);
            Assert.That(created.StatusCode, Is.EqualTo(HttpStatusCode.Created));
            Assert.That((await Json(created)).GetProperty("price").GetDecimal(), Is.EqualTo(75.5m));

            HttpResponseMessage invalid = await Send(HttpMethod.Post, "/api/products",
                new { name = "", price = -1 }, adminToken);
            Assert.That(invalid.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That((await Json(invalid)).TryGetProperty("error", out _), Is.True);
        }

        [Test]
        public async Task Logout_FuncionaSinAccessToken_YRevocaElRefreshToken()
        {
            string refreshToken = (await Login("user", "User123!")).GetProperty("refresh_token").GetString()!;
            var body = new { refresh_token = refreshToken };

            HttpResponseMessage logout = await Send(HttpMethod.Post, "/api/auth/logout", body);
            HttpResponseMessage refresh = await Send(HttpMethod.Post, "/api/auth/refresh", body);

            Assert.That(logout.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(refresh.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }

        [Test]
        public async Task LoginsFallidosRepetidos_SeLimitanCon429()
        {
            var bad = new { username = "limitado", password = "mala" };
            for (int i = 0; i < 5; i++)
            {
                HttpResponseMessage failed = await Send(HttpMethod.Post, "/api/auth/login", bad);
                Assert.That(failed.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            }

            HttpResponseMessage blocked = await Send(HttpMethod.Post, "/api/auth/login", bad);

            Assert.That(blocked.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
            Assert.That(blocked.Headers.RetryAfter, Is.Not.Null);
        }

        [Test]
        public async Task Health_EsPublico()
        {
            HttpResponseMessage response = await _client.GetAsync("/health");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Headers.GetValues("X-Content-Type-Options"), Does.Contain("nosniff"));
        }

        private async Task<JsonElement> Login(string username, string password)
        {
            HttpResponseMessage response = await Send(HttpMethod.Post, "/api/auth/login", new { username, password });
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            return await Json(response);
        }

        private async Task<string> AccessToken(string username, string password) =>
            (await Login(username, password)).GetProperty("access_token").GetString()!;

        private async Task<JsonElement> GetJson(string path, string? accessToken = null)
        {
            HttpResponseMessage response = await Send(HttpMethod.Get, path, null, accessToken);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            return await Json(response);
        }

        private Task<HttpResponseMessage> Send(HttpMethod method, string path, object? body, string? accessToken = null)
        {
            var request = new HttpRequestMessage(method, path);
            if (body is not null)
                request.Content = JsonContent.Create(body);
            if (accessToken is not null)
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            return _client.SendAsync(request);
        }

        private static async Task<JsonElement> Json(HttpResponseMessage response) =>
            JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
    }
}
