# Dockerfile del front Blazor Server JwtAuthImplFront.
# El contexto de build es la RAÍZ de la solución (ver docker-compose.yml),
# porque este proyecto referencia al proyecto hermano JwtAuthImpl.

# --- Etapa de compilación ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Primero solo los .csproj para aprovechar la caché de restore.
COPY JwtAuthImpl/JwtAuthImpl.csproj JwtAuthImpl/
COPY JwtAuthImplFront/JwtAuthImplFront.csproj JwtAuthImplFront/
RUN dotnet restore JwtAuthImplFront/JwtAuthImplFront.csproj

# Ahora el resto del código fuente y se publica.
COPY JwtAuthImpl/ JwtAuthImpl/
COPY JwtAuthImplFront/ JwtAuthImplFront/
RUN dotnet publish JwtAuthImplFront/JwtAuthImplFront.csproj -c Release -o /app --no-restore

# --- Etapa de ejecución ---
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# La imagen aspnet:8.0 ya escucha en el puerto 8080 por defecto (ASPNETCORE_HTTP_PORTS).
EXPOSE 8080
ENTRYPOINT ["dotnet", "JwtAuthImplFront.dll"]
