using JwtAuthImpl.Auth;
using JwtAuthImpl.Products;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace JwtAuthImpl.Extensions
{
    /// <summary>
    /// Registro de la implementación cliente de JWT en el contenedor de DI.
    /// Mantiene al front (Blazor) desacoplado de los detalles de autenticación.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        /// <summary>
        /// Registra los clientes HTTP tipados hacia la JwtAuthApi (autenticación
        /// y productos), el almacén de tokens y el proveedor de estado de
        /// autenticación, además del soporte de autorización y estado en cascada
        /// para Blazor.
        /// </summary>
        /// <param name="services">Colección de servicios.</param>
        /// <param name="apiBaseUrl">URL base de la JwtAuthApi.</param>
        /// <param name="acceptAnyServerCertificate">
        /// Si es true, acepta certificados TLS no confiables (solo para desarrollo
        /// con el certificado autofirmado de la API local).
        /// </param>
        public static IServiceCollection AddJwtAuthClient(
            this IServiceCollection services,
            string apiBaseUrl,
            bool acceptAnyServerCertificate = false)
        {
            // Configuración común a todos los clientes tipados hacia la API.
            void ConfigureClient(HttpClient client) => client.BaseAddress = new Uri(apiBaseUrl);

            HttpMessageHandler ConfigureHandler()
            {
                var handler = new HttpClientHandler();
                if (acceptAnyServerCertificate)
                {
                    handler.ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                }
                return handler;
            }

            // Cliente de autenticación (endpoints api/auth/*).
            services.AddHttpClient<AuthApiClient>(ConfigureClient)
                .ConfigurePrimaryHttpMessageHandler(ConfigureHandler);

            // Canal HTTP compartido para los clientes de negocio (adjunta token
            // y refresca ante 401). El refresco lo aporta AuthApiClient.
            services.AddHttpClient<ApiHttpClient>(ConfigureClient)
                .ConfigurePrimaryHttpMessageHandler(ConfigureHandler);
            services.AddScoped<ITokenRefresher>(sp => sp.GetRequiredService<AuthApiClient>());

            // Cliente de productos (contenido de ejemplo). Usa el canal compartido.
            services.AddScoped<ProductsApiClient>();

            services.AddScoped<ITokenStore, TokenStore>();
            services.AddScoped<RefreshCoordinator>();
            services.AddScoped<JwtAuthenticationStateProvider>();
            services.AddScoped<AuthenticationStateProvider>(sp =>
                sp.GetRequiredService<JwtAuthenticationStateProvider>());

            services.AddAuthorizationCore();
            services.AddCascadingAuthenticationState();

            return services;
        }
    }
}
