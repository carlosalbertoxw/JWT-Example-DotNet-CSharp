using JwtAuth.Configuration;
using JwtAuth.Security;
using JwtAuth.Services;
using JwtAuth.Stores;
using JwtAuth.Tokens;

namespace JwtAuthTest
{
    [TestFixture]
    public class AuthServiceTests
    {
        private JwtSettings _settings = null!;
        private ITokenService _tokenService = null!;
        private IRefreshTokenStore _refreshStore = null!;
        private IUserStore _userStore = null!;
        private AuthService _authService = null!;

        [SetUp]
        public void SetUp()
        {
            _settings = TestHelpers.CreateSettings();
            var hasher = new Pbkdf2PasswordHasher();
            _tokenService = new TokenService(_settings);
            _refreshStore = new InMemoryRefreshTokenStore();
            _userStore = new InMemoryUserStore(hasher);

            _authService = new AuthService(_userStore, hasher, _tokenService, _refreshStore, _settings);
        }

        [Test]
        public void Login_DeberiaEmitirTokens_ConCredencialesValidas()
        {
            AuthResult result = _authService.Login("admin", "Admin123!");

            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Tokens, Is.Not.Null);
            Assert.That(result.Tokens!.AccessToken, Is.Not.Empty);
            Assert.That(result.Tokens.RefreshToken, Is.Not.Empty);
            // El access token emitido debe ser válido.
            Assert.That(_tokenService.ValidateAccessToken(result.Tokens.AccessToken), Is.Not.Null);
        }

        [Test]
        public void Login_DeberiaFallar_ConContrasenaIncorrecta()
        {
            AuthResult result = _authService.Login("admin", "incorrecta");

            Assert.That(result.Succeeded, Is.False);
            Assert.That(result.Tokens, Is.Null);
            Assert.That(result.Error, Is.Not.Null);
        }

        [Test]
        public void Login_DeberiaFallar_ConUsuarioInexistente()
        {
            AuthResult result = _authService.Login("fantasma", "lo-que-sea");

            Assert.That(result.Succeeded, Is.False);
        }

        [Test]
        public void Refresh_DeberiaEmitirNuevosTokens_ConRefreshValido()
        {
            string refreshToken = _authService.Login("admin", "Admin123!").Tokens!.RefreshToken;

            AuthResult result = _authService.Refresh(refreshToken);

            Assert.That(result.Succeeded, Is.True);
            Assert.That(result.Tokens!.RefreshToken, Is.Not.EqualTo(refreshToken));
        }

        [Test]
        public void Refresh_DeberiaRevocarElRefreshAnterior_RotacionDeTokens()
        {
            string refreshToken = _authService.Login("admin", "Admin123!").Tokens!.RefreshToken;

            _authService.Refresh(refreshToken);
            // El token ya usado no puede volver a utilizarse.
            AuthResult segundoIntento = _authService.Refresh(refreshToken);

            Assert.That(segundoIntento.Succeeded, Is.False);
        }

        [Test]
        public void Refresh_DeberiaFallar_ConRefreshInexistente()
        {
            Assert.That(_authService.Refresh("token-que-no-existe").Succeeded, Is.False);
        }

        [Test]
        public void Logout_DeberiaRevocarElRefreshToken()
        {
            string refreshToken = _authService.Login("admin", "Admin123!").Tokens!.RefreshToken;

            bool loggedOut = _authService.Logout(refreshToken);

            Assert.That(loggedOut, Is.True);
            // Tras el logout, el refresh token ya no sirve.
            Assert.That(_authService.Refresh(refreshToken).Succeeded, Is.False);
        }

        [Test]
        public void Logout_DeberiaRetornarFalse_ConRefreshInexistente()
        {
            Assert.That(_authService.Logout("inexistente"), Is.False);
        }
    }
}
