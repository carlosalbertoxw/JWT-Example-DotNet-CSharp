using JwtAuthImpl.Auth;
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
        /// Registra el cliente HTTP tipado hacia la JwtAuthApi, el almacén de
        /// tokens y el proveedor de estado de autenticación, además del soporte
        /// de autorización y estado en cascada para Blazor.
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
            services.AddHttpClient<AuthApiClient>(client =>
                {
                    client.BaseAddress = new Uri(apiBaseUrl);
                })
                .ConfigurePrimaryHttpMessageHandler(() =>
                {
                    var handler = new HttpClientHandler();
                    if (acceptAnyServerCertificate)
                    {
                        handler.ServerCertificateCustomValidationCallback =
                            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    }
                    return handler;
                });

            services.AddScoped<ITokenStore, TokenStore>();
            services.AddScoped<JwtAuthenticationStateProvider>();
            services.AddScoped<AuthenticationStateProvider>(sp =>
                sp.GetRequiredService<JwtAuthenticationStateProvider>());

            services.AddAuthorizationCore();
            services.AddCascadingAuthenticationState();

            return services;
        }
    }
}
