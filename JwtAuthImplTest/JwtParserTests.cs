using System.Security.Claims;
using JwtAuthImpl.Auth;
using JwtAuthImplTest.Helpers;

namespace JwtAuthImplTest
{
    [TestFixture]
    public class JwtParserTests
    {
        [Test]
        public void ParseClaimsFromJwt_DeberiaExtraerUsernameYRoles()
        {
            string token = TestJwt.Create("carlos", new[] { "Admin", "User" });

            var claims = JwtParser.ParseClaimsFromJwt(token).ToList();

            Assert.That(claims.First(c => c.Type == "username").Value, Is.EqualTo("carlos"));

            string[] roles = claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToArray();
            Assert.That(roles, Is.EquivalentTo(new[] { "Admin", "User" }));
        }

        [Test]
        public void IsExpired_DeberiaSerFalse_ParaTokenVigente()
        {
            string token = TestJwt.Create(expires: DateTimeOffset.UtcNow.AddMinutes(10));

            Assert.That(JwtParser.IsExpired(token), Is.False);
        }

        [Test]
        public void IsExpired_DeberiaSerTrue_ParaTokenExpirado()
        {
            Assert.That(JwtParser.IsExpired(TestJwt.Expired()), Is.True);
        }

        [Test]
        public void IsExpired_DeberiaSerTrue_SiNoHayClaimExp()
        {
            Assert.That(JwtParser.IsExpired(TestJwt.WithoutExpiration()), Is.True);
        }

        [Test]
        public void IsExpired_DeberiaSerTrue_ParaTextoQueNoEsJwt()
        {
            Assert.That(JwtParser.IsExpired("esto-no-es-un-jwt"), Is.True);
        }

        [Test]
        public void ParseClaimsFromJwt_DeberiaRetornarVacio_ParaEntradaInvalida()
        {
            Assert.That(JwtParser.ParseClaimsFromJwt("sin-puntos"), Is.Empty);
        }
    }
}
