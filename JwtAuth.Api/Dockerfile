# Dockerfile de la API JwtAuth.Api.
# El contexto de build es la RAÍZ de la solución (ver docker-compose.yml),
# porque este proyecto referencia a los proyectos hermanos JwtAuth y JwtAuth.Data.

# --- Etapa de compilación ---
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Primero solo los .csproj (y la config común) para aprovechar la caché de restore.
COPY Directory.Build.props Directory.Packages.props ./
COPY JwtAuth/JwtAuth.csproj JwtAuth/
COPY JwtAuth.Data/JwtAuth.Data.csproj JwtAuth.Data/
COPY JwtAuth.Api/JwtAuth.Api.csproj JwtAuth.Api/
RUN dotnet restore JwtAuth.Api/JwtAuth.Api.csproj

# Ahora el resto del código fuente y se publica.
COPY JwtAuth/ JwtAuth/
COPY JwtAuth.Data/ JwtAuth.Data/
COPY JwtAuth.Api/ JwtAuth.Api/
RUN dotnet publish JwtAuth.Api/JwtAuth.Api.csproj -c Release -o /app --no-restore

# --- Etapa de ejecución ---
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Usuario sin privilegios que ya trae la imagen de .NET: si alguien explotara
# la app, no tendría root en el contenedor.
USER $APP_UID

# La imagen aspnet:10.0 ya escucha en el puerto 8080 por defecto (ASPNETCORE_HTTP_PORTS).
EXPOSE 8080
ENTRYPOINT ["dotnet", "JwtAuth.Api.dll"]
