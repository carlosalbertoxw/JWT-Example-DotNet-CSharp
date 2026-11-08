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
            Role = AppUser.AdminRole
        };

        [Test]
        public async Task CreateAccessToken_DeberiaSerValidadoConLosClaimsDelContrato()
        {
            var service = new TokenService(TestHelpers.CreateSettings());
            AppUser user = CreateUser();

            string token = service.CreateAccessToken(user);
            ClaimsPrincipal? principal = await TestHelpers.ValidateAsync(token, TestHelpers.CreateSettings());

            Assert.That(principal, Is.Not.Null);
            Assert.That(principal!.Identity?.Name, Is.EqualTo("carlos"));
            Assert.That(principal.FindFirst("sub")?.Value, Is.EqualTo(user.Id.ToString()));
            Assert.That(principal.FindFirst("role")?.Value, Is.EqualTo("Admin"));
            Assert.That(principal.IsInRole("Admin"), Is.True);
        }

        [Test]
        public async Task ValidateAccessToken_DeberiaRetornarNull_ConTokenManipulado()
        {
            var service = new TokenService(TestHelpers.CreateSettings());
            string token = service.CreateAccessToken(CreateUser());

            // Se altera el último carácter para invalidar la firma.
            string tampered = token[..^2] + (token[^1] == 'A' ? 'B' : 'A');

            Assert.That(await TestHelpers.ValidateAsync(tampered, TestHelpers.CreateSettings()), Is.Null);
        }

        [Test]
        public async Task ValidateAccessToken_DeberiaRetornarNull_ConTokenExpirado()
        {
            // Emitido hace una hora con 15 minutos de vida.
            var past = new ManualTimeProvider(DateTimeOffset.UtcNow.AddHours(-1));
            var emisor = new TokenService(TestHelpers.CreateSettings(), past);
            string token = emisor.CreateAccessToken(CreateUser());

            Assert.That(await TestHelpers.ValidateAsync(token, TestHelpers.CreateSettings()), Is.Null);
        }

        [Test]
        public async Task ValidateAccessToken_DeberiaRetornarNull_ConOtraClaveEmisorOAudiencia()
        {

            JwtSettings otraClave = TestHelpers.CreateSettings();
            otraClave.SigningKey = "una-clave-de-firma-completamente-distinta-0987654321";
            JwtSettings otroEmisor = TestHelpers.CreateSettings();
            otroEmisor.Issuer = "otro";
            JwtSettings otraAudiencia = TestHelpers.CreateSettings();
            otraAudiencia.Audience = "otra";

            foreach (JwtSettings settings in new[] { otraClave, otroEmisor, otraAudiencia })
            {
                string token = new TokenService(settings).CreateAccessToken(CreateUser());
                Assert.That(await TestHelpers.ValidateAsync(token, TestHelpers.CreateSettings()), Is.Null);
            }
        }

        [Test]
        public async Task ValidateAccessToken_DeberiaRetornarNull_ConTextoNoToken()
        {
            var service = new TokenService(TestHelpers.CreateSettings());

            Assert.That(await TestHelpers.ValidateAsync("no-es-un-jwt", TestHelpers.CreateSettings()), Is.Null);
        }

        [Test]
        public void GenerateRefreshToken_DeberiaProducirValoresUnicosDe64Hex()
        {
            var service = new TokenService(TestHelpers.CreateSettings());

            string a = service.GenerateRefreshToken();
            string b = service.GenerateRefreshToken();

            Assert.That(a, Has.Length.EqualTo(64));
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
