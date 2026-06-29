using JwtAuth.Configuration;
using JwtAuth.Security;
using JwtAuth.Services;
using JwtAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace JwtAuth.Extensions
{
    /// <summary>
    /// Registro de los componentes de validación JWT en el contenedor de DI.
    /// Mantiene a la API ajena a los detalles de implementación de JWT.
    /// </summary>
    /// <remarks>
    /// Esta extensión solo registra la lógica de validación/emisión (hasher,
    /// servicio de tokens y servicio de autenticación). Los almacenes de datos
    /// (usuarios y refresh tokens) los provee la capa de datos mediante
    /// <c>AddJwtAuthData()</c> en el proyecto JwtAuthDatos.
    /// </remarks>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registra el sistema de autenticación JWT (servicio de tokens, hasher
        /// y servicio de autenticación) usando la configuración provista. Los
        /// almacenes de datos deben registrarse aparte con <c>AddJwtAuthData()</c>.
        /// </summary>
        public static IServiceCollection AddJwtAuth(this IServiceCollection services, JwtSettings settings)
        {
            ArgumentNullException.ThrowIfNull(settings);

            services.AddSingleton(settings);
            services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
            services.AddSingleton<ITokenService, TokenService>();
            services.AddScoped<IAuthService, AuthService>();

            return services;
        }
    }
}
