namespace JwtAuth.Security
{
    /// <summary>
    /// Abstracción para el hashing y verificación de contraseñas.
    /// </summary>
    public interface IPasswordHasher
    {
        /// <summary>Genera un hash (con salt incluido) para la contraseña dada.</summary>
        string Hash(string password);

        /// <summary>Verifica una contraseña en texto plano contra un hash existente.</summary>
        bool Verify(string password, string hash);

        /// <summary>
        /// Hash "señuelo" de una cadena descartable. Cuando el usuario no existe
        /// se verifica contra él para que el tiempo de respuesta sea el mismo que
        /// con un usuario real y no revele qué usuarios existen.
        /// </summary>
        string DecoyHash { get; }
    }
}
