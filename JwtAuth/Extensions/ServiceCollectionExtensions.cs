using JwtAuth.Configuration;
using JwtAuth.Security;
using JwtAuth.Services;
using JwtAuth.Stores;
using JwtAuth.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace JwtAuth.Extensions
{
    /// <summary>
    /// Registro de los componentes de la librería en el contenedor de DI.
    /// Mantiene a la API ajena a los detalles de implementación de JWT.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registra el sistema de autenticación JWT (servicio de tokens, stores,
        /// hasher y servicio de autenticación) usando la configuración provista.
        /// </summary>
        public static IServiceCollection AddJwtAuth(this IServiceCollection services, JwtSettings settings)
        {
            ArgumentNullException.ThrowIfNull(settings);

            services.AddSingleton(settings);
            services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
            services.AddSingleton<ITokenService, TokenService>();
            services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
            services.AddSingleton<IUserStore, InMemoryUserStore>();
            services.AddScoped<IAuthService, AuthService>();

            return services;
        }
    }
}
