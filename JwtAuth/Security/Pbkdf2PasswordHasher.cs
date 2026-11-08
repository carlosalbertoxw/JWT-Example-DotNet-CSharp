using System.Security.Cryptography;

namespace JwtAuth.Security
{
    /// <summary>
    /// Implementación de <see cref="IPasswordHasher"/> basada en PBKDF2
    /// (Rfc2898) con SHA-256. El salt se genera de forma aleatoria por cada
    /// contraseña y se almacena junto al hash con el formato:
    /// <c>{iteraciones}.{saltBase64}.{hashBase64}</c>. Guardar las iteraciones
    /// permite subirlas en el futuro sin invalidar los hashes existentes.
    /// </summary>
    public class Pbkdf2PasswordHasher : IPasswordHasher
    {
        /// <summary>Recomendación de OWASP (2023) para PBKDF2-HMAC-SHA256.</summary>
        public const int DefaultIterations = 600_000;

        private const int SaltSize = 16;       // 128 bits
        private const int KeySize = 32;        // 256 bits
        private static readonly HashAlgorithmName Algorithm = HashAlgorithmName.SHA256;
        private const char Separator = '.';

        private readonly int _iterations;
        private readonly Lazy<string> _decoyHash;

        public Pbkdf2PasswordHasher() : this(DefaultIterations)
        {
        }

        /// <summary>Permite bajar las iteraciones en pruebas para que corran rápido.</summary>
        public Pbkdf2PasswordHasher(int iterations)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
            _iterations = iterations;
            _decoyHash = new Lazy<string>(() => Hash(Convert.ToBase64String(RandomNumberGenerator.GetBytes(16))));
        }

        public string DecoyHash => _decoyHash.Value;

        public string Hash(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("La contraseña no puede estar vacía.", nameof(password));

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, _iterations, Algorithm, KeySize);

            return string.Join(
                Separator,
                _iterations,
                Convert.ToBase64String(salt),
                Convert.ToBase64String(key));
        }

        public bool Verify(string password, string hash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(hash))
                return false;

            string[] parts = hash.Split(Separator, 3);
            if (parts.Length != 3)
                return false;

            if (!int.TryParse(parts[0], out int iterations) || iterations < 1)
                return false;

            byte[] salt;
            byte[] expectedKey;
            try
            {
                salt = Convert.FromBase64String(parts[1]);
                expectedKey = Convert.FromBase64String(parts[2]);
            }
            catch (FormatException)
            {
                return false;
            }

            byte[] actualKey = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, Algorithm, expectedKey.Length);

            // Comparación en tiempo constante para evitar ataques de temporización.
            return CryptographicOperations.FixedTimeEquals(actualKey, expectedKey);
        }
    }
}
