using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using JwtAuth.Configuration;
using JwtAuth.Extensions;
using JwtAuth.Security;
using JwtAuth.Stores;
using JwtAuth.Tokens;
using JwtAuthApi.Contracts;
using JwtAuthApi.OpenApi;
using JwtAuthApi.Services;
using JwtAuthDatos.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// --- Configuración JWT (sección "Jwt") ---
var jwtSettings = builder.Configuration
    .GetSection(JwtSettings.SectionName)
    .Get<JwtSettings>() ?? new JwtSettings();

// Ninguna clave se versiona: llega por Jwt__SigningKey (variable de entorno o
// secret manager). Fuera de desarrollo es obligatoria; en desarrollo, si falta,
// se genera una aleatoria al arrancar (los tokens dejan de valer al reiniciar).
bool generatedDevKey = false;
if (string.IsNullOrWhiteSpace(jwtSettings.SigningKey))
{
    if (!builder.Environment.IsDevelopment())
    {
        throw new InvalidOperationException(
            "Jwt:SigningKey no está configurada. Defina una clave propia (>= 32 bytes) " +
            "mediante la variable de entorno Jwt__SigningKey o un secret manager.");
    }
    jwtSettings.SigningKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(JwtSettings.MinSigningKeyBytes));
    generatedDevKey = true;
}

// Registra la validación/emisión JWT (proyecto JwtAuth) y la capa de datos
// (proyecto JwtAuthDatos) que provee los almacenes de usuarios, refresh tokens,
// intentos de login y productos.
builder.Services.AddJwtAuth(jwtSettings);
builder.Services.AddJwtAuthData();

// Límite de intentos de login/refresh: por cuenta y por IP (ver AuthController).
var rateLimit = builder.Configuration.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>()
    ?? new RateLimitOptions();
builder.Services.AddSingleton(sp =>
{
    var attempts = sp.GetRequiredService<IAttemptStore>();
    var time = sp.GetRequiredService<TimeProvider>();
    var window = TimeSpan.FromSeconds(rateLimit.WindowSeconds);
    return new AuthRateLimits(
        new RateLimiter(attempts, rateLimit.AccountMaxAttempts, window, time),
        new RateLimiter(attempts, rateLimit.IpMaxAttempts, window, time));
});

// Purga periódica de refresh tokens expirados del almacén.
builder.Services.AddHostedService<RefreshTokenCleanupService>();

// Autenticación con bearer JWT, reutilizando los parámetros de validación
// de la librería (única fuente de verdad, sin instanciar el servicio aquí).
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Conserva los nombres cortos de los claims del contrato (sub, username, role)
        // en lugar de traducirlos a las URIs largas de ClaimTypes.
        options.MapInboundClaims = false;
        options.TokenValidationParameters = TokenService.CreateValidationParameters(jwtSettings);

        // Errores 401/403 con el mismo formato que el resto de la API.
        options.Events = new JwtBearerEvents
        {
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new ErrorResponse("Falta el access token o es inválido"));
            },
            OnForbidden = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return context.Response.WriteAsJsonAsync(new ErrorResponse("Se requiere el rol Admin"));
            }
        };
    });

builder.Services.AddAuthorization();

// --- Forwarded Headers (proxy inverso) ---
// Tras un proxy/balanceador, la IP que ve Kestrel es la del proxy, no la del
// cliente. Sin esto, el rate limiting agruparía a todos los clientes en la misma
// IP. SEGURIDAD: solo se confía en proxies conocidos; de lo contrario un cliente
// podría falsear X-Forwarded-For y evadir el límite de intentos.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownProxies.Clear();
    options.KnownIPNetworks.Clear();

    string[] knownProxies = builder.Configuration
        .GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [];
    foreach (string proxy in knownProxies)
    {
        if (IPAddress.TryParse(proxy, out IPAddress? ip))
            options.KnownProxies.Add(ip);
    }
});

// Contrato común de los ejemplos: JSON en snake_case y errores {"error": "..."}.
builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower)
    .ConfigureApiBehaviorOptions(o => o.InvalidModelStateResponseFactory = context =>
    {
        string message = context.ModelState.Values
            .SelectMany(v => v.Errors)
            .Select(e => string.IsNullOrEmpty(e.ErrorMessage) ? "Petición inválida" : e.ErrorMessage)
            .FirstOrDefault() ?? "Petición inválida";
        return new BadRequestObjectResult(new ErrorResponse(message));
    });

// Documento OpenAPI nativo de .NET (/openapi/v1.json) con el esquema Bearer,
// para que Swagger UI muestre el botón "Authorize".
builder.Services.AddOpenApi(options => options.AddDocumentTransformer<BearerSecuritySchemeTransformer>());

// Liveness en /health (lo usa el healthcheck de Docker).
builder.Services.AddHealthChecks();

var app = builder.Build();

if (generatedDevKey)
{
    app.Logger.LogWarning(
        "Jwt:SigningKey no está definida: se generó una clave aleatoria de desarrollo.");
}

// Debe ir de primero: corrige RemoteIpAddress/esquema antes de que cualquier
// middleware posterior (HTTPS redirect, rate limiting) los lea.
app.UseForwardedHeaders();

// Cabeceras de seguridad para todas las respuestas.
app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options => options.SwaggerEndpoint("/openapi/v1.json", "JwtAuthApi v1"));
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHealthChecks("/health");

app.Run();

/// <summary>Expuesta para las pruebas de integración (WebApplicationFactory).</summary>
public partial class Program;
