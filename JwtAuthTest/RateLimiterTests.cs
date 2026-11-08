using JwtAuth.Security;
using JwtAuthDatos.Stores;

namespace JwtAuthTest
{
    [TestFixture]
    public class RateLimiterTests
    {
        private ManualTimeProvider _time = null!;
        private RateLimiter _limiter = null!;

        [SetUp]
        public void SetUp()
        {
            _time = new ManualTimeProvider(DateTimeOffset.UtcNow);
            _limiter = new RateLimiter(new InMemoryAttemptStore(), 3, TimeSpan.FromMinutes(1), _time);
        }

        [Test]
        public void DeberiaBloquear_AlAlcanzarElLimite_YReportarRetryAfter()
        {
            for (int i = 0; i < 3; i++)
                _limiter.RecordFailure("login:user:admin");

            Assert.That(_limiter.TooManyAttempts("login:user:admin"), Is.True);
            Assert.That(_limiter.RetryAfterSeconds("login:user:admin"), Is.InRange(1, 60));
        }

        [Test]
        public void CadaClaveSeLimitaPorSeparado_YClearReinicia()
        {
            for (int i = 0; i < 3; i++)
                _limiter.RecordFailure("login:user:admin");

            Assert.That(_limiter.TooManyAttempts("login:user:user"), Is.False);
            _limiter.Clear("login:user:admin");
            Assert.That(_limiter.TooManyAttempts("login:user:admin"), Is.False);
        }

        [Test]
        public void LosFallosFueraDeLaVentanaNoCuentan()
        {
            for (int i = 0; i < 3; i++)
                _limiter.RecordFailure("login:ip:10.0.0.1");

            _time.Advance(TimeSpan.FromSeconds(61));

            Assert.That(_limiter.TooManyAttempts("login:ip:10.0.0.1"), Is.False);
        }
    }
}
