using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace JwtAuthApi.OpenApi
{
    /// <summary>
    /// Agrega al documento OpenAPI el esquema de seguridad Bearer JWT, para que
    /// Swagger UI muestre el botón "Authorize" y se puedan probar los endpoints
    /// protegidos pegando el access token.
    /// </summary>
    internal sealed class BearerSecuritySchemeTransformer : IOpenApiDocumentTransformer
    {
        private const string SchemeName = "Bearer";

        public Task TransformAsync(
            OpenApiDocument document, OpenApiDocumentTransformerContext context, CancellationToken cancellationToken)
        {
            document.Info.Title = "JwtAuthApi";
            document.Info.Description =
                "API de ejemplo JWT (contrato común con los ejemplos en Java y PHP). " +
                "Usuarios de prueba: admin / Admin123! (rol Admin) y user / User123! (rol User).";

            document.Components ??= new OpenApiComponents();
            document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
            document.Components.SecuritySchemes[SchemeName] = new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT",
                Description = "Access token obtenido en /api/auth/login (sin el prefijo \"Bearer\")."
            };

            document.Security ??= [];
            document.Security.Add(new OpenApiSecurityRequirement
            {
                [new OpenApiSecuritySchemeReference(SchemeName, document)] = []
            });

            return Task.CompletedTask;
        }
    }
}
