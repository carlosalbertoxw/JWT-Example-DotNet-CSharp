using System.Net;
using System.Threading.RateLimiting;
using JwtAuth.Configuration;
using JwtAuth.Extensions;
using JwtAuth.Tokens;
using JwtAuthApi.Services;
using JwtAuthDatos.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// --- Configuración JWT (sección "Jwt") ---
// En desarrollo la clave se toma de appsettings.Development.json. En producción
// debe inyectarse por variable de entorno o secret manager (nunca versionarla).
var jwtSettings = builder.Configuration
    .GetSection(JwtSettings.SectionName)
    .Get<JwtSettings>() ?? new JwtSettings();

// Guardia de arranque: fuera de desarrollo, no se permite arrancar con una clave
// vacía o con el valor de ejemplo. Evita firmar tokens con un secreto conocido.
const string ExampleSigningKey =
    "clave-super-secreta-de-ejemplo-cambiar-en-produccion-1234567890";
if (!builder.Environment.IsDevelopment() &&
    (string.IsNullOrWhiteSpace(jwtSettings.SigningKey) || jwtSettings.SigningKey == ExampleSigningKey))
{
    throw new InvalidOperationException(
        "Jwt:SigningKey no está configurada o usa el valor de ejemplo. " +
        "Defina una clave propia (>= 32 bytes) mediante variable de entorno " +
        "Jwt__SigningKey o un secret manager antes de desplegar.");
}

// Registra la validación/emisión JWT (proyecto JwtAuth) y la capa de datos
// (proyecto JwtAuthDatos) que provee los almacenes de usuarios, refresh tokens
// y productos. La separación deja a JwtAuth ajeno a cómo se persisten los datos.
builder.Services.AddJwtAuth(jwtSettings);
builder.Services.AddJwtAuthData();

// Lógica de productos (contenido de ejemplo, ajeno a JWT).
builder.Services.AddScoped<IProductService, ProductService>();

// Purga periódica de refresh tokens expirados del almacén.
builder.Services.AddHostedService<RefreshTokenCleanupService>();

// Autenticación con bearer JWT, reutilizando los parámetros de validación
// de la librería (única fuente de verdad, sin instanciar el servicio aquí).
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = TokenService.CreateValidationParameters(jwtSettings);
    });

builder.Services.AddAuthorization();

// --- Forwarded Headers (proxy inverso) ---
// Tras un proxy/balanceador (Nginx, contenedor, LB de nube), la IP que ve Kestrel
// es la del proxy, no la del cliente. Sin esto, el rate limiter agruparía a todos
// los clientes en la misma partición. Este middleware reescribe RemoteIpAddress con
// la IP real tomada de X-Forwarded-For (y el esquema de X-Forwarded-Proto).
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;

    // SEGURIDAD: solo se confían las cabeceras provenientes de proxies conocidos.
    // De lo contrario, un cliente podría falsear su IP en X-Forwarded-For y evadir
    // el rate limiting. Se parte de cero (sin confiar en nadie) y se añaden las IPs
    // reales del/los proxy(s) desde la sección "ForwardedHeaders:KnownProxies".
    // Si no se configura ninguna, las cabeceras se ignoran (comportamiento seguro
    // para desarrollo con Kestrel directo).
    options.KnownProxies.Clear();
    options.KnownNetworks.Clear();

    string[] knownProxies = builder.Configuration
        .GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? Array.Empty<string>();
    foreach (string proxy in knownProxies)
    {
        if (IPAddress.TryParse(proxy, out IPAddress? ip))
            options.KnownProxies.Add(ip);
    }
});

// --- Rate limiting para los endpoints de autenticación ---
// Limita los intentos de login/refresh por IP para frenar fuerza bruta y abuso.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromSeconds(30),
                QueueLimit = 0
            }));
});

builder.Services.AddControllers();

// Swagger con soporte para enviar el bearer token desde la UI.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "JwtAuthApi", Version = "v1" });

    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "Ingrese el access token con el prefijo 'Bearer'. Ej: \"Bearer eyJ...\"",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Reference = new OpenApiReference
        {
            Type = ReferenceType.SecurityScheme,
            Id = JwtBearerDefaults.AuthenticationScheme
        }
    };

    options.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, securityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { securityScheme, Array.Empty<string>() }
    });
});

var app = builder.Build();

// Debe ir de primero: corrige RemoteIpAddress/esquema antes de que cualquier
// middleware posterior (HTTPS redirect, rate limiter) los lea.
app.UseForwardedHeaders();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
