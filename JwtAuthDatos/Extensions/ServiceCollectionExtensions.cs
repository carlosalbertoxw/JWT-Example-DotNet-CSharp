using JwtAuth.Stores;
using JwtAuthDatos.Stores;
using Microsoft.Extensions.DependencyInjection;

namespace JwtAuthDatos.Extensions
{
    /// <summary>
    /// Registro de la capa de datos en el contenedor de DI. Provee las
    /// implementaciones concretas de los almacenes (usuarios, refresh tokens y
    /// productos), manteniendo a las capas superiores ajenas a la persistencia.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registra los almacenes de datos en memoria. En producción esta sería
        /// la única extensión a cambiar para apuntar a una base de datos real.
        /// </summary>
        public static IServiceCollection AddJwtAuthData(this IServiceCollection services)
        {
            services.AddSingleton<IUserStore, InMemoryUserStore>();
            services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
            services.AddSingleton<IProductStore, InMemoryProductStore>();

            return services;
        }
    }
}
