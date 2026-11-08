using JwtAuthDatos.Stores;

namespace JwtAuthTest
{
    [TestFixture]
    public class InMemoryRefreshTokenStoreTests
    {
        private static readonly DateTime Now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private InMemoryRefreshTokenStore _store = null!;

        [SetUp]
        public void SetUp() => _store = new InMemoryRefreshTokenStore();

        private void Add(string value, Guid userId, int days = 7) =>
            _store.Add(value, userId, Now.AddDays(days));

        [Test]
        public void AddYFind_DeberiaRecuperarElToken()
        {
            var userId = Guid.NewGuid();
            Add("abc", userId);

            var found = _store.Find("abc");

            Assert.That(found, Is.Not.Null);
            Assert.That(found!.UserId, Is.EqualTo(userId));
            Assert.That(_store.Find("inexistente"), Is.Null);
        }

        [Test]
        public void TryConsume_DeberiaFuncionarUnaSolaVez()
        {
            Add("abc", Guid.NewGuid());

            Assert.That(_store.TryConsume("abc", Now), Is.True);
            Assert.That(_store.TryConsume("abc", Now), Is.False);
            Assert.That(_store.Find("abc")!.IsRevoked, Is.True);
        }

        [Test]
        public void TryConsume_DeberiaFallar_SiExpiro()
        {
            Add("abc", Guid.NewGuid(), days: 1);

            Assert.That(_store.TryConsume("abc", Now.AddDays(2)), Is.False);
            Assert.That(_store.Find("abc")!.IsRevoked, Is.False, "expirado no es lo mismo que reusado");
        }

        [Test]
        public void Revoke_DeberiaRetornarFalse_SiNoExiste()
        {
            Assert.That(_store.Revoke("inexistente", Now), Is.False);
        }

        [Test]
        public void RevokeAllForUser_DeberiaRevocarSoloLosDelUsuario()
        {
            var user1 = Guid.NewGuid();
            var user2 = Guid.NewGuid();
            Add("t1", user1);
            Add("t2", user1);
            Add("t3", user2);

            _store.RevokeAllForUser(user1, Now);

            Assert.That(_store.Find("t1")!.IsRevoked, Is.True);
            Assert.That(_store.Find("t2")!.IsRevoked, Is.True);
            Assert.That(_store.Find("t3")!.IsRevoked, Is.False);
        }

        [Test]
        public void RemoveExpired_DeberiaQuitarSoloLosExpirados()
        {
            var userId = Guid.NewGuid();
            Add("vigente", userId, days: 7);
            Add("expirado", userId, days: -1);
            // Revocado pero aún no expirado: debe conservarse para detectar reuso.
            Add("revocado-vigente", userId, days: 7);
            _store.Revoke("revocado-vigente", Now);

            int removed = _store.RemoveExpired(Now);

            Assert.That(removed, Is.EqualTo(1));
            Assert.That(_store.Find("expirado"), Is.Null);
            Assert.That(_store.Find("vigente"), Is.Not.Null);
            Assert.That(_store.Find("revocado-vigente"), Is.Not.Null);
        }
    }
}
