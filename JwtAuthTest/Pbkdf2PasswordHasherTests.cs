using JwtAuth.Security;

namespace JwtAuthTest
{
    [TestFixture]
    public class Pbkdf2PasswordHasherTests
    {
        private Pbkdf2PasswordHasher _hasher = null!;

        [SetUp]
        public void SetUp() => _hasher = new Pbkdf2PasswordHasher(TestHelpers.FastIterations);

        [Test]
        public void Hash_DeberiaProducirHashesDistintosParaLaMismaContrasena()
        {
            string hash1 = _hasher.Hash("Secreta123!");
            string hash2 = _hasher.Hash("Secreta123!");

            // El salt aleatorio garantiza hashes diferentes.
            Assert.That(hash1, Is.Not.EqualTo(hash2));
        }

        [Test]
        public void Verify_DeberiaRetornarTrue_ConLaContrasenaCorrecta()
        {
            string hash = _hasher.Hash("Secreta123!");

            Assert.That(_hasher.Verify("Secreta123!", hash), Is.True);
        }

        [Test]
        public void Verify_DeberiaRetornarFalse_ConLaContrasenaIncorrecta()
        {
            string hash = _hasher.Hash("Secreta123!");

            Assert.That(_hasher.Verify("Incorrecta", hash), Is.False);
        }

        [Test]
        public void Verify_DeberiaRetornarFalse_ConHashMalFormado()
        {
            Assert.That(_hasher.Verify("Secreta123!", "esto-no-es-un-hash"), Is.False);
        }

        [Test]
        public void Hash_DeberiaLanzar_ConContrasenaVacia()
        {
            Assert.That(() => _hasher.Hash(string.Empty), Throws.ArgumentException);
        }

        [Test]
        public void Verify_DeberiaAceptarHashesConOtrasIteraciones()
        {
            // El hash guarda sus iteraciones: subirlas no invalida contraseñas viejas.
            string viejo = new Pbkdf2PasswordHasher(500).Hash("Secreta123!");

            Assert.That(_hasher.Verify("Secreta123!", viejo), Is.True);
            Assert.That(viejo, Does.StartWith("500."));
        }

        [Test]
        public void DecoyHash_DeberiaSerUnHashValidoQueNoCoincide()
        {
            Assert.That(_hasher.Verify("cualquiera", _hasher.DecoyHash), Is.False);
            Assert.That(_hasher.DecoyHash.Split('.'), Has.Length.EqualTo(3));
        }
    }
}
