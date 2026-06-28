using System.Security.Claims;
using JwtAuth.Configuration;
using JwtAuth.Models;
using JwtAuth.Tokens;

namespace JwtAuthTest
{
    [TestFixture]
    public class TokenServiceTests
    {
        private static AppUser CreateUser() => new()
        {
            Id = Guid.NewGuid(),
            Username = "carlos",
            Roles = new[] { "Admin", "User" }
        };

        [Test]
        public void CreateAccessToken_DeberiaSerValidadoCorrectamente()
        {
            var service = new TokenService(TestHelpers.CreateSettings());
            AppUser user = CreateUser();

            (string token, DateTime expires) = service.CreateAccessToken(user);
            ClaimsPrincipal? principal = service.ValidateAccessToken(token);

            Assert.That(principal, Is.Not.Null);
            Assert.That(expires, Is.GreaterThan(DateTime.UtcNow));
            Assert.That(principal!.FindFirst("username")?.Value, Is.EqualTo("carlos"));
            Assert.That(principal.FindFirst(ClaimTypes.NameIdentifier)?.Value, Is.EqualTo(user.Id.ToString()));
        }

        [Test]
        public void ValidateAccessToken_DeberiaIncluirLosRoles()
        {
            var service = new TokenService(TestHelpers.CreateSettings());

            (string token, _) = service.CreateAccessToken(CreateUser());
            ClaimsPrincipal principal = service.ValidateAccessToken(token)!;

            string[] roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
            Assert.That(roles, Is.EquivalentTo(new[] { "Admin", "User" }));
        }

        [Test]
        public void ValidateAccessToken_DeberiaRetornarNull_ConTokenManipulado()
        {
            var service = new TokenService(TestHelpers.CreateSettings());
            (string token, _) = service.CreateAccessToken(CreateUser());

            // Se altera el último carácter para invalidar la firma.
            string tampered = token[..^2] + (token[^1] == 'A' ? 'B' : 'A');

            Assert.That(service.ValidateAccessToken(tampered), Is.Null);
        }

        [Test]
        public void ValidateAccessToken_DeberiaRetornarNull_ConTokenExpirado()
        {
            // Access token de 0 minutos: ya nace expirado.
            var service = new TokenService(TestHelpers.CreateSettings(accessTokenMinutes: 0));
            (string token, _) = service.CreateAccessToken(CreateUser());

            Assert.That(service.ValidateAccessToken(token), Is.Null);
        }

        [Test]
        public void ValidateAccessToken_DeberiaRetornarNull_ConOtraClaveDeFirma()
        {
            var emisor = new TokenService(TestHelpers.CreateSettings());
            (string token, _) = emisor.CreateAccessToken(CreateUser());

            var otraConfig = TestHelpers.CreateSettings();
            otraConfig.SigningKey = "una-clave-de-firma-completamente-distinta-0987654321";
            var validador = new TokenService(otraConfig);

            Assert.That(validador.ValidateAccessToken(token), Is.Null);
        }

        [Test]
        public void ValidateAccessToken_DeberiaRetornarNull_ConTextoNoToken()
        {
            var service = new TokenService(TestHelpers.CreateSettings());

            Assert.That(service.ValidateAccessToken("no-es-un-jwt"), Is.Null);
        }

        [Test]
        public void GenerateRefreshToken_DeberiaProducirValoresUnicos()
        {
            var service = new TokenService(TestHelpers.CreateSettings());

            string a = service.GenerateRefreshToken();
            string b = service.GenerateRefreshToken();

            Assert.That(a, Is.Not.Empty);
            Assert.That(a, Is.Not.EqualTo(b));
        }

        [Test]
        public void Constructor_DeberiaLanzar_ConClaveDemasiadoCorta()
        {
            var settings = new JwtSettings
            {
                Issuer = "i",
                Audience = "a",
                SigningKey = "corta"
            };

            Assert.That(() => new TokenService(settings), Throws.ArgumentException);
        }
    }
}
