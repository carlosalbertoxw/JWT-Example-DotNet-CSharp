# Dockerfile del front Blazor Server JwtAuthImplFront.
# El contexto de build es la RAÍZ de la solución (ver docker-compose.yml),
# porque este proyecto referencia al proyecto hermano JwtAuthImpl.

# --- Etapa de compilación ---
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Primero solo los .csproj (y la config común) para aprovechar la caché de restore.
COPY Directory.Build.props ./
COPY JwtAuthImpl/JwtAuthImpl.csproj JwtAuthImpl/
COPY JwtAuthImplFront/JwtAuthImplFront.csproj JwtAuthImplFront/
RUN dotnet restore JwtAuthImplFront/JwtAuthImplFront.csproj

# Ahora el resto del código fuente y se publica.
COPY JwtAuthImpl/ JwtAuthImpl/
COPY JwtAuthImplFront/ JwtAuthImplFront/
# Sin --no-restore: el SDK agrega los assets de Blazor (blazor.web.js) solo si
# ve los archivos .razor, que no existían en el restore inicial con los .csproj.
RUN dotnet publish JwtAuthImplFront/JwtAuthImplFront.csproj -c Release -o /app

# --- Etapa de ejecución ---
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Carpeta de las claves de Data Protection (se monta como volumen en compose);
# se crea aquí para que el volumen herede el dueño y el usuario app pueda escribir.
RUN mkdir -p /home/app/keys && chown $APP_UID /home/app/keys

# Usuario sin privilegios que ya trae la imagen de .NET: si alguien explotara
# la app, no tendría root en el contenedor.
USER $APP_UID

# La imagen aspnet:10.0 ya escucha en el puerto 8080 por defecto (ASPNETCORE_HTTP_PORTS).
EXPOSE 8080
ENTRYPOINT ["dotnet", "JwtAuthImplFront.dll"]
