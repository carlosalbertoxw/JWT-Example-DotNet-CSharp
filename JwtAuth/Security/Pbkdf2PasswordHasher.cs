using System.Security.Cryptography;

namespace JwtAuth.Security
{
    /// <summary>
    /// Implementación de <see cref="IPasswordHasher"/> basada en PBKDF2
    /// (Rfc2898) con SHA-256. El salt se genera de forma aleatoria por cada
    /// contraseña y se almacena junto al hash con el formato:
    /// <c>{iteraciones}.{saltBase64}.{hashBase64}</c>.
    /// </summary>
    public class Pbkdf2PasswordHasher : IPasswordHasher
    {
        private const int SaltSize = 16;       // 128 bits
        private const int KeySize = 32;        // 256 bits
        private const int Iterations = 100_000;
        private static readonly HashAlgorithmName Algorithm = HashAlgorithmName.SHA256;
        private const char Separator = '.';

        public string Hash(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("La contraseña no puede estar vacía.", nameof(password));

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, Algorithm, KeySize);

            return string.Join(
                Separator,
                Iterations,
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

            if (!int.TryParse(parts[0], out int iterations))
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
