using JwtAuthImpl.Extensions;
using JwtAuthImplFront.Components;

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

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
