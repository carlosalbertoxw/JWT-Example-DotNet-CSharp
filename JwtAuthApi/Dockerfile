# Dockerfile de la API JwtAuthApi.
# El contexto de build es la RAÍZ de la solución (ver docker-compose.yml),
# porque este proyecto referencia a los proyectos hermanos JwtAuth y JwtAuthDatos.

# --- Etapa de compilación ---
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Primero solo los .csproj para aprovechar la caché de restore.
COPY JwtAuth/JwtAuth.csproj JwtAuth/
COPY JwtAuthDatos/JwtAuthDatos.csproj JwtAuthDatos/
COPY JwtAuthApi/JwtAuthApi.csproj JwtAuthApi/
RUN dotnet restore JwtAuthApi/JwtAuthApi.csproj

# Ahora el resto del código fuente y se publica.
COPY JwtAuth/ JwtAuth/
COPY JwtAuthDatos/ JwtAuthDatos/
COPY JwtAuthApi/ JwtAuthApi/
RUN dotnet publish JwtAuthApi/JwtAuthApi.csproj -c Release -o /app --no-restore

# --- Etapa de ejecución ---
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# La imagen aspnet:8.0 ya escucha en el puerto 8080 por defecto (ASPNETCORE_HTTP_PORTS).
EXPOSE 8080
ENTRYPOINT ["dotnet", "JwtAuthApi.dll"]
