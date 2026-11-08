using JwtAuth.Configuration;
using JwtAuth.Security;
using JwtAuth.Services;
using JwtAuth.Stores;
using JwtAuth.Tokens;
using JwtAuthDatos.Stores;

namespace JwtAuthTest
{
    [TestFixture]
    public class AuthServiceTests
    {
        private JwtSettings _settings = null!;
        private ManualTimeProvider _time = null!;
        private ITokenService _tokenService = null!;
        private IRefreshTokenStore _refreshStore = null!;
        private AuthService _authService = null!;

        [SetUp]
        public void SetUp()
        {
            _settings = TestHelpers.CreateSettings();
            _time = new ManualTimeProvider(DateTimeOffset.UtcNow);
            var hasher = new Pbkdf2PasswordHasher(TestHelpers.FastIterations);
            _tokenService = new TokenService(_settings);
            _refreshStore = new InMemoryRefreshTokenStore();

            _authService = new AuthService(
                new InMemoryUserStore(hasher), hasher, _tokenService, _refreshStore, _settings, _time);
        }

        [Test]
        public async Task Login_DeberiaEmitirTokens_ConCredencialesValidas()
        {
            AuthResult result = _authService.Login("admin", "Admin123!");

            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Tokens!.AccessToken, Is.Not.Empty);
            Assert.That(result.Tokens.RefreshToken, Is.Not.Empty);
            Assert.That(result.Tokens.ExpiresInSeconds, Is.EqualTo(15 * 60));
            // El access token emitido debe ser válido y llevar el rol.
            var principal = await TestHelpers.ValidateAsync(result.Tokens.AccessToken, _settings);
            Assert.That(principal?.IsInRole("Admin"), Is.True);
        }

        [Test]
        public void Login_DeberiaFallar_ConContrasenaIncorrectaOUsuarioInexistente()
        {
            Assert.That(_authService.Login("admin", "incorrecta").Succeeded, Is.False);
            Assert.That(_authService.Login("fantasma", "lo-que-sea").Succeeded, Is.False);
        }

        [Test]
        public void Refresh_DeberiaRotarElToken()
        {
            string refreshToken = _authService.Login("admin", "Admin123!").Tokens!.RefreshToken;

            AuthResult result = _authService.Refresh(refreshToken);

            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Tokens!.RefreshToken, Is.Not.EqualTo(refreshToken));
            // El token ya usado no puede volver a utilizarse.
            Assert.That(_authService.Refresh(refreshToken).Succeeded, Is.False);
        }

        [Test]
        public void Refresh_DeberiaFallar_ConRefreshInexistenteOExpirado()
        {
            Assert.That(_authService.Refresh("token-que-no-existe").Succeeded, Is.False);

            string refreshToken = _authService.Login("user", "User123!").Tokens!.RefreshToken;
            _time.Advance(TimeSpan.FromDays(8));

            Assert.That(_authService.Refresh(refreshToken).Succeeded, Is.False);
        }

        [Test]
        public void Refresh_DeberiaRevocarTodaLaFamilia_AlDetectarReuso()
        {
            string r1 = _authService.Login("admin", "Admin123!").Tokens!.RefreshToken;
            string r2 = _authService.Refresh(r1).Tokens!.RefreshToken;

            // Reutilización de r1 (ya rotado): debe fallar y, además, revocar
            // toda la familia, dejando r2 también inservible.
            Assert.That(_authService.Refresh(r1).Succeeded, Is.False);
            Assert.That(_authService.Refresh(r2).Succeeded, Is.False,
                "tras detectar reuso, el token vigente de la familia también debe revocarse");
        }

        [Test]
        public async Task Refresh_Concurrente_SoloUnaPeticionDeberiaGanar()
        {
            string refreshToken = _authService.Login("user", "User123!").Tokens!.RefreshToken;
            using var start = new ManualResetEventSlim(false);

            Task<bool>[] attempts = Enumerable.Range(0, 8)
                .Select(_ => Task.Run(() =>
                {
                    start.Wait();
                    return _authService.Refresh(refreshToken).Succeeded;
                }))
                .ToArray();
            start.Set();
            bool[] results = await Task.WhenAll(attempts);

            Assert.That(results.Count(ok => ok), Is.EqualTo(1),
                "solo una petición puede canjear el mismo refresh token");
        }

        [Test]
        public void Logout_DeberiaCerrarSoloLaSesionDelTokenEnviado()
        {
            string phone = _authService.Login("user", "User123!").Tokens!.RefreshToken;
            string laptop = _authService.Login("user", "User123!").Tokens!.RefreshToken;

            _authService.Logout(phone);

            Assert.That(_authService.Refresh(laptop).Succeeded, Is.True,
                "la otra sesión debe seguir activa tras el logout");
            Assert.That(_refreshStore.Find(phone)!.IsRevoked, Is.True);
        }

        [Test]
        public void Logout_NoDeberiaFallar_ConRefreshInexistente()
        {
            Assert.That(() => _authService.Logout("inexistente"), Throws.Nothing);
        }
    }
}
