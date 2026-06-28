using JwtAuth.Models;
using JwtAuth.Stores;

namespace JwtAuthTest
{
    [TestFixture]
    public class InMemoryRefreshTokenStoreTests
    {
        private InMemoryRefreshTokenStore _store = null!;

        [SetUp]
        public void SetUp() => _store = new InMemoryRefreshTokenStore();

        private static RefreshToken NewToken(string value, Guid userId, int days = 7) => new()
        {
            Token = value,
            UserId = userId,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(days)
        };

        [Test]
        public void AddYFind_DeberiaRecuperarElTokenAgregado()
        {
            var token = NewToken("abc", Guid.NewGuid());
            _store.Add(token);

            Assert.That(_store.Find("abc"), Is.SameAs(token));
        }

        [Test]
        public void Find_DeberiaRetornarNull_SiNoExiste()
        {
            Assert.That(_store.Find("inexistente"), Is.Null);
        }

        [Test]
        public void Revoke_DeberiaMarcarElTokenComoInactivo()
        {
            _store.Add(NewToken("abc", Guid.NewGuid()));

            bool revoked = _store.Revoke("abc");

            Assert.That(revoked, Is.True);
            Assert.That(_store.Find("abc")!.IsActive, Is.False);
        }

        [Test]
        public void Revoke_DeberiaRetornarFalse_SiNoExiste()
        {
            Assert.That(_store.Revoke("inexistente"), Is.False);
        }

        [Test]
        public void RevokeAllForUser_DeberiaRevocarSoloLosDelUsuario()
        {
            var user1 = Guid.NewGuid();
            var user2 = Guid.NewGuid();
            _store.Add(NewToken("t1", user1));
            _store.Add(NewToken("t2", user1));
            _store.Add(NewToken("t3", user2));

            _store.RevokeAllForUser(user1);

            Assert.That(_store.Find("t1")!.IsActive, Is.False);
            Assert.That(_store.Find("t2")!.IsActive, Is.False);
            Assert.That(_store.Find("t3")!.IsActive, Is.True);
        }

        [Test]
        public void IsActive_DeberiaSerFalse_ParaTokenExpirado()
        {
            var token = NewToken("expirado", Guid.NewGuid(), days: -1);
            _store.Add(token);

            Assert.That(_store.Find("expirado")!.IsActive, Is.False);
        }
    }
}
