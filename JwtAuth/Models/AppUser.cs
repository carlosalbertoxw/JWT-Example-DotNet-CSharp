namespace JwtAuth.Models
{
    /// <summary>
    /// Representa un usuario de la aplicación. En un sistema real estos datos
    /// provendrían de una base de datos; aquí sirven para demostrar el flujo.
    /// </summary>
    public class AppUser
    {
        public const string AdminRole = "Admin";
        public const string UserRole = "User";

        public Guid Id { get; set; } = Guid.NewGuid();

        public string Username { get; set; } = string.Empty;

        /// <summary>Hash de la contraseña (nunca se almacena en texto plano).</summary>
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>Rol único del usuario ("Admin" o "User"), usado para autorización.</summary>
        public string Role { get; set; } = UserRole;
    }
}
