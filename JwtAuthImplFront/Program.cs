using JwtAuthImpl.Extensions;
using JwtAuthImplFront.Components;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// --- Integración con la JwtAuthApi ---
// Toda la implementación cliente de JWT vive en el proyecto JwtAuthImpl;
// el front solo la registra indicando la URL de la API.
string apiBaseUrl = builder.Configuration["ApiBaseUrl"] ?? "https://localhost:7036";

builder.Services.AddJwtAuthClient(
    apiBaseUrl,
    acceptAnyServerCertificate: builder.Environment.IsDevelopment());

// Los tokens se guardan en el navegador cifrados con Data Protection
// (ProtectedLocalStorage). Si las claves de cifrado no se persisten, cada
// reinicio del contenedor genera claves nuevas y todas las sesiones se pierden.
// En Docker se guardan en un volumen (ver docker-compose.yml).
string? keysPath = builder.Configuration["DataProtection:KeysPath"];
if (!string.IsNullOrWhiteSpace(keysPath))
{
    builder.Services.AddDataProtection()
        .SetApplicationName("JwtAuthImplFront")
        .PersistKeysToFileSystem(new DirectoryInfo(keysPath));
}

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

// Cabeceras de seguridad. La CSP solo permite recursos del propio sitio (scripts,
// estilos, la conexión WebSocket del circuito de Blazor); 'unsafe-inline' en estilos
// lo exige la UI de reconexión que Blazor inyecta con estilos en línea.
app.Use(async (context, next) =>
{
    context.Response.Headers.ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; " +
        "base-uri 'self'; form-action 'self'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "same-origin";
    await next();
});

app.UseHttpsRedirection();

app.MapStaticAssets();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
