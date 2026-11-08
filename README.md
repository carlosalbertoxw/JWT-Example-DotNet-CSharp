# JWT-Example-DotNet-CSharp

Ejemplo de autenticación basada en **JWT (JSON Web Tokens)** con **.NET 10 / C#**, que
muestra un flujo completo de *login*, *refresh token con rotación*, *logout* y acceso
a endpoints protegidos por autenticación y por rol.

La API implementa el **contrato común** de los ejemplos JWT (el mismo que las versiones
en Java y PHP): JSON en `snake_case` (`access_token`, `refresh_token`, `expires_in`),
rol único `Admin`/`User` en el claim `role`, `/api/auth/me` y productos con `id`,
`name`, `description` y `price`. Así, cualquier cliente de la serie (Vaadin, web PHP,
Android o este Blazor) funciona contra cualquiera de las APIs.

La solución está dividida en proyectos para separar responsabilidades en capas:
la **validación/emisión de JWT**, el **acceso a datos** y la **capa web** quedan
**desacoplados** y se pueden probar de forma aislada. Incluye además un cliente
**Blazor** que consume la API.

---

## Estructura de la solución

```
JWT-Example-DotNet-CSharp/
├── JwtAuth/                → Librería de validación/emisión JWT (sin dependencia de ASP.NET Core)
├── JwtAuthDatos/           → Capa de datos: almacenes de usuarios, refresh tokens, intentos de login y productos
├── JwtAuthApi/             → Web API que expone los endpoints de autenticación y ejemplos
├── JwtAuthTest/            → Pruebas unitarias (NUnit) de JwtAuth y JwtAuthDatos
├── JwtAuthApiTest/         → Pruebas de integración de la API (WebApplicationFactory)
├── JwtAuthImpl/            → Implementación cliente de JWT (consumo de la API), desacoplada del front
├── JwtAuthImplFront/        → App Blazor (Interactive Server): solo la UI, referencia a JwtAuthImpl
└── JwtAuthImplTest/        → Pruebas (NUnit + bUnit) de la implementación cliente y los componentes
```

### Capas y dependencias (backend)

```
JwtAuthApi ──► JwtAuth        (emisión y parámetros de validación; contratos IUserStore / IRefreshTokenStore / IAttemptStore)
     │
     └───────► JwtAuthDatos ──► JwtAuth   (implementa los contratos + almacén de productos)
```

`JwtAuth` define **qué** se necesita (interfaces) pero no **cómo** se persiste;
`JwtAuthDatos` aporta las implementaciones. Así, cambiar a una base de datos real
no toca la lógica de validación: basta con sustituir la capa de datos.

### `JwtAuth` — validación/emisión JWT (class library)

Contiene **solo la lógica de emisión de tokens y los parámetros para validarlos**, más
los **contratos** (interfaces) de los almacenes. No conoce cómo se persisten los datos.

| Archivo | Responsabilidad |
|---|---|
| `Configuration/JwtSettings.cs` | Parámetros de configuración: issuer, audience, clave de firma, tiempos de vida. |
| `Models/AppUser.cs` | Usuario de la aplicación (id, username, hash de contraseña y rol único `Admin`/`User`). |
| `Models/RefreshToken.cs` | Refresh token persistido: dueño, expiración y fecha de revocación (`IsRevoked`, `IsExpired`). |
| `Models/TokenPair.cs` | Par emitido en login/refresh: access token, refresh token y segundos de vida del access token. |
| `Security/IPasswordHasher.cs` + `Pbkdf2PasswordHasher.cs` | Hashing de contraseñas con PBKDF2-SHA256 (600 000 iteraciones, salt aleatorio, comparación en tiempo constante) y hash señuelo contra la enumeración de usuarios por tiempo. |
| `Security/RateLimiter.cs` + `Stores/IAttemptStore.cs` | Límite de intentos fallidos con ventana deslizante (por cuenta y por IP). |
| `Tokens/ITokenService.cs` + `TokenService.cs` | Emisión de access tokens (HMAC-SHA256, con `JsonWebTokenHandler`) y de refresh tokens. `CreateValidationParameters(...)` da los parámetros con que el middleware JwtBearer de la API valida cada token. |
| `Stores/IUserStore.cs` | **Contrato** del repositorio de usuarios (la implementación vive en `JwtAuthDatos`). |
| `Stores/IRefreshTokenStore.cs` | **Contrato** del almacén de refresh tokens: canje atómico (`TryConsume`), revocación y purga. |
| `Services/IAuthService.cs` + `AuthService.cs` | Orquesta login, refresh (con rotación) y logout. Devuelve `AuthResult`. |
| `Extensions/ServiceCollectionExtensions.cs` | `AddJwtAuth(...)`: registra la validación/emisión en DI. **No registra los almacenes** (eso lo hace `JwtAuthDatos`). |

> La librería **no referencia ASP.NET Core**. Solo depende de
> `Microsoft.IdentityModel.JsonWebTokens` y
> `Microsoft.Extensions.DependencyInjection.Abstractions`. Así puede reutilizarse
> desde cualquier tipo de aplicación (consola, worker, otra API) y probarse sin levantar un host web.

### `JwtAuthDatos` — capa de datos (class library)

Provee las **implementaciones** de los almacenes. Es la única capa que sabe *cómo* se
guardan los datos; referencia a `JwtAuth` para implementar sus contratos. En este
ejemplo todo es **en memoria**, pero para migrar a una base de datos real basta con
cambiar este proyecto, sin tocar `JwtAuth` ni `JwtAuthApi`.

| Archivo | Responsabilidad |
|---|---|
| `Stores/InMemoryUserStore.cs` | Implementa `IUserStore`. Siembra los usuarios `admin` y `user` (con contraseñas hasheadas). |
| `Stores/InMemoryRefreshTokenStore.cs` | Implementa `IRefreshTokenStore`; guarda solo el **hash** SHA-256 de cada token y canjea con un lock por token. |
| `Stores/InMemoryAttemptStore.cs` | Implementa `IAttemptStore` (intentos fallidos de login/refresh). |
| `Stores/IProductStore.cs` + `InMemoryProductStore.cs` | Almacén del catálogo de productos (contenido de ejemplo, ajeno a JWT). |
| `Extensions/ServiceCollectionExtensions.cs` | `AddJwtAuthData()`: registra los cuatro almacenes en DI. **Único punto a cambiar para apuntar a una BD real.** |

### `JwtAuthApi` — Web API

| Archivo | Responsabilidad |
|---|---|
| `Program.cs` | Registra la validación JWT (`AddJwtAuth`) y la capa de datos (`AddJwtAuthData`); configura el bearer JWT (reutilizando los `TokenValidationParameters` del `TokenService`), JSON en snake_case, errores `{"error": ...}`, OpenAPI nativo + Swagger UI con botón **Authorize**, `/health` y cabeceras de seguridad. |
| `Contracts/*.cs` | DTOs de entrada/salida del contrato común. |
| `Controllers/AuthController.cs` | Endpoints `login`, `refresh`, `logout` y `me`, con límite de intentos por cuenta y por IP (429 + `Retry-After`). |
| `Controllers/ProductsController.cs` | Recurso de ejemplo con tres niveles de acceso: público (sin precio), autenticado (con precio) y por rol (alta, solo `Admin`). Usa directamente `IProductStore`. |
| `OpenApi/BearerSecuritySchemeTransformer.cs` | Agrega el esquema Bearer al documento OpenAPI. |
| `Services/RefreshTokenCleanupService.cs` | Purga periódica de refresh tokens expirados. |

> La lógica de **autenticación** (`AuthController`/`IAuthService`) y la de **productos**
> (`ProductsController`/`IProductStore`) están separadas: los productos son solo
> contenido de ejemplo y no se mezclan con el flujo JWT.

### `JwtAuthTest` — pruebas unitarias (NUnit)

Pruebas del hasher de contraseñas, el `TokenService`, el `RateLimiter`, el
`InMemoryRefreshTokenStore` (de `JwtAuthDatos`) y el `AuthService` (login, rotación,
reuso, refresh concurrente y logout por sesión).

### `JwtAuthApiTest` — pruebas de integración

Levantan la API en memoria con `WebApplicationFactory` y la ejercitan por HTTP:
formato del contrato, 401/403/400 con `{"error": ...}`, logout sin access token,
límite de intentos (429) y `/health`.

### `JwtAuthImpl` — implementación cliente de JWT (class library)

Encapsula **todo el consumo de la JwtAuthApi**, desacoplado de la UI. El front solo
referencia esta librería y la registra con una llamada. Usa `FrameworkReference` a
`Microsoft.AspNetCore.App` porque depende de tipos de ASP.NET Core Components.

Al igual que en la API, la **autenticación** y los **productos** están separados en
clases distintas: `AuthApiClient` solo conoce los endpoints `api/auth/*`, mientras que
`ProductsApiClient` consume los de productos reutilizando la infraestructura HTTP común.

| Archivo | Responsabilidad |
|---|---|
| `Models/AuthModels.cs` / `ApiModels.cs` | DTOs que reflejan los contratos de la API. |
| `Auth/JwtParser.cs` | Lee los claims del JWT (sin validar la firma) y detecta expiración. |
| `Auth/TokenStore.cs` | Persiste access/refresh tokens con `ProtectedLocalStorage` (cifrado en servidor). |
| `Auth/AuthApiClient.cs` | Cliente HTTP tipado de **autenticación**: login, refresh y logout. Implementa `ITokenRefresher`. |
| `Auth/ApiHttpClient.cs` | Canal HTTP compartido por los clientes de negocio: adjunta el bearer y hace **reintento + refresh automático ante 401**. |
| `Auth/ITokenRefresher.cs` | Abstrae el refresco para que `ApiHttpClient` lo dispare sin acoplarse a `AuthApiClient`. |
| `Products/ProductsApiClient.cs` | Cliente HTTP tipado de **productos** (catálogo público, listado protegido, alta). Sin plomería de auth. |
| `Auth/JwtAuthenticationStateProvider.cs` | `AuthenticationStateProvider` que arma el `ClaimsPrincipal` desde el token y renueva si expiró. |
| `Extensions/ServiceCollectionExtensions.cs` | `AddJwtAuthClient(apiBaseUrl, ...)`: registra los clientes HTTP (auth y productos), stores y proveedor de estado. |

### `JwtAuthImplFront` — cliente Blazor (Interactive Server)

Aplicación Blazor que contiene **solo la UI** (componentes y páginas) y delega toda la
autenticación en `JwtAuthImpl`. En `Program.cs` basta con:

```csharp
builder.Services.AddJwtAuthClient(apiBaseUrl,
    acceptAnyServerCertificate: builder.Environment.IsDevelopment());
```

| Archivo | Responsabilidad |
|---|---|
| `Components/Pages/Login.razor` | Formulario de inicio de sesión. Solo acepta `returnUrl` locales (evita redirecciones abiertas). |
| `Components/Pages/PublicCatalog.razor` | Catálogo público (`/catalog`): consume el endpoint anónimo, sin login. |
| `Components/Pages/Products.razor` | Página protegida que lista productos y permite crear (solo `Admin`). |
| `Components/Layout/NavMenu.razor` | Navegación con catálogo público y login/logout según el estado de sesión. |

Detalles relevantes:

- El **prerenderizado está deshabilitado** (`InteractiveServerRenderMode(prerender: false)`
  en `App.razor`) porque `ProtectedLocalStorage` requiere JS interop, disponible solo
  una vez establecido el circuito interactivo.
- La **autorización se aplica del lado cliente**, no a nivel de ruta/servidor. Como el
  token vive en `localStorage`, el servidor no conoce la sesión durante el render estático
  (SSR); por eso no se usa el atributo `[Authorize]` (que provocaría un `ChallengeAsync`
  en el SSR sin servicio de autenticación). En su lugar, cada página protegida verifica el
  estado autenticado dentro del circuito interactivo y redirige al login si hace falta.
  La protección por rol se hace con `<AuthorizeView Roles="Admin">`.
- La URL de la API se configura en `appsettings.json` (`ApiBaseUrl`). En desarrollo se
  acepta el certificado autofirmado de la API local.
- Los tokens se cifran con **Data Protection** antes de guardarse en el navegador. Si se
  define `DataProtection:KeysPath`, las claves de cifrado se persisten ahí (en Docker, en
  un volumen) para que reiniciar el contenedor no cierre todas las sesiones.
- El **logout** envía solo el refresh token (sin access token): así funciona aunque el
  access token ya haya expirado.
- Al ser **Blazor Server**, las llamadas a la API salen desde el servidor (no desde el
  navegador), por lo que **no requiere configuración CORS** en la API.

### `JwtAuthImplTest` — pruebas del cliente y los componentes

Pruebas con **NUnit** y **bUnit** sobre `JwtAuthImpl` y los componentes del front.
Para no depender de JS interop, `TokenStore` se abstrae con `ITokenStore` y se sustituye
por uno en memoria; las llamadas HTTP se simulan con un `FakeHttpMessageHandler`.

| Área | Qué cubre |
|---|---|
| `JwtParserTests` | Extracción de claims (username, rol) y detección de expiración. |
| `AuthApiClientTests` | Login (éxito y fallo) y logout sin access token que limpia el store. |
| `ProductsApiClientTests` | Catálogo público (sin token), bearer en endpoints protegidos, **401 → refresh → reintento** y código HTTP al crear. |
| `JwtAuthenticationStateProviderTests` | Anónimo sin token, principal con nombre/rol, refresco al expirar, limpieza si el refresh falla. |
| `Components/NavMenuTests` | Enlaces según estado de sesión (login vs. usuario + logout) y catálogo público. |
| `Components/ProductsTests` | Redirección al login si anónimo; sección "crear" solo con rol `Admin`. |
| `Components/LoginTests` | Envío del formulario: navegación en éxito, mensaje de error en fallo y `returnUrl` externos rechazados. |

```bash
dotnet test JwtAuthImplTest/JwtAuthImplTest.csproj
```

---

## Cómo ejecutar

Requisitos: **.NET 10 SDK**.

```bash
# Restaurar y compilar toda la solución
dotnet build JwtExample.slnx

# Ejecutar todas las pruebas
dotnet test JwtExample.slnx

# Levantar la API (Swagger se abre en la raíz en modo Development)
dotnet run --project JwtAuthApi/JwtAuthApi.csproj
```

Por defecto la API queda escuchando en `http://localhost:5274` y
`https://localhost:7036` (ver `JwtAuthApi/Properties/launchSettings.json`).
La UI de Swagger queda disponible en `/swagger` (documento OpenAPI en `/openapi/v1.json`).

En desarrollo, si no defines `Jwt:SigningKey` (p. ej. con `dotnet user-secrets`), la API
genera una clave aleatoria al arrancar: los tokens dejan de valer al reiniciar.

### Ejecutar el cliente Blazor junto con la API

El cliente Blazor espera la API en `https://localhost:7036` (configurable con
`ApiBaseUrl`). Levanta **ambos** proyectos (en terminales separadas):

```bash
# Terminal 1 — API (perfil https para exponer el puerto 7036)
dotnet run --project JwtAuthApi/JwtAuthApi.csproj --launch-profile https

# Terminal 2 — cliente Blazor
dotnet run --project JwtAuthImplFront/JwtAuthImplFront.csproj
```

Luego abre la app Blazor en el navegador, ve a **Iniciar sesión** y usa uno de los
usuarios de ejemplo. Desde Visual Studio puedes configurar ambos como *proyectos de
inicio* (Configurar proyectos de inicio → Varios proyectos).

### Ejecutar con Docker Compose

Como alternativa a instalar el SDK, ambas aplicaciones se pueden levantar en
contenedores. Requisitos: **Docker** (con Compose v2).

```bash
docker compose up --build
```

| Servicio | URL | Descripción |
|---|---|---|
| `front` | `http://localhost:5070` | Cliente Blazor (punto de entrada para el usuario). |
| `api` | `http://localhost:5274/swagger` | API + Swagger UI. |

Para detenerlos:

```bash
docker compose down
```

Cada aplicación tiene su propio `Dockerfile` multi-etapa (compila con la imagen
`sdk:10.0` y ejecuta sobre la ligera `aspnet:10.0` con un usuario sin privilegios), orquestados por
[`docker-compose.yml`](docker-compose.yml). Detalles a tener en cuenta:

- **Contexto de build en la raíz:** cada `Dockerfile` se construye desde la raíz de la
  solución porque los proyectos referencian a sus hermanos (`JwtAuth`/`JwtAuthDatos` la
  API, `JwtAuthImpl` el front).
- **Red interna:** dentro de Compose el front llama a la API por el **nombre del
  servicio** (`ApiBaseUrl=http://api:8080`), no por `localhost`. Los contenedores
  escuchan en el puerto `8080` (por defecto en la imagen `aspnet:10.0`) y se publican en
  los puertos `5070`/`5274` del host.
- **Clave de firma:** ninguna clave se versiona. Si defines `JWT_SIGNING_KEY` (p. ej. en
  un archivo `.env`), compose la pasa como `Jwt__SigningKey`; si no, la API genera una
  aleatoria al arrancar. Fuera de `Development` es obligatoria (≥ 32 bytes).
- **Health check:** compose espera a que la API responda en `/health` antes de arrancar
  el front.
- **Entorno:** se ejecutan en `ASPNETCORE_ENVIRONMENT=Development` para exponer Swagger.
  Como la comunicación interna es HTTP, la advertencia `Failed to determine the https
  port for redirect` en los logs es esperada e inofensiva.

### Usuarios de ejemplo

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `Admin123!` | `Admin` |
| `user`  | `User123!`  | `User` |

---

## Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| `POST` | `/api/auth/login`   | Pública | Valida credenciales y devuelve un par de tokens (429 tras varios fallos). |
| `POST` | `/api/auth/refresh` | Pública | Renueva el par de tokens a partir de un refresh token válido (rota el anterior). |
| `POST` | `/api/auth/logout`  | Pública | Revoca el refresh token enviado (cierra solo esa sesión). |
| `GET`  | `/api/auth/me`      | Bearer  | Devuelve los claims del usuario autenticado. |
| `GET`  | `/api/products/public` | Pública | Catálogo visible para cualquiera, **sin precio**. |
| `GET`  | `/api/products`     | Bearer  | Listado completo **con precio**. |
| `POST` | `/api/products`     | Rol `Admin` | Crea un producto (lo agrega al catálogo en memoria). |
| `GET`  | `/health`           | Pública | Liveness (lo usa el healthcheck de Docker). |

---

## Flujo de uso

### 1. Login

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "admin", "password": "Admin123!" }
```

Respuesta:

```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "9f2c...64 caracteres hex...",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

### 2. Llamar a un endpoint protegido

Se envía el **access token** en el header `Authorization` en cada petición:

```http
GET /api/products
Authorization: Bearer eyJhbGc...
```

### 3. Refrescar cuando el access token expira

El access token dura poco (15 min). Cuando expira, la API responde `401`.
En lugar de volver a pedir credenciales, se usa el **refresh token**:

```http
POST /api/auth/refresh
Content-Type: application/json

{ "refresh_token": "9f2c..." }
```

Devuelve un **par nuevo** (access + refresh). Se reemplazan ambos en el cliente.

### 4. Logout

Revoca el refresh token para que no pueda volver a usarse. No requiere access token: el
refresh token es la credencial, así el cliente puede cerrar sesión aunque el access token
ya haya expirado (sin tener que renovarlo, lo que rotaría el refresh token justo al salir).

```http
POST /api/auth/logout
Content-Type: application/json

{ "refresh_token": "9f2c..." }
```

> El archivo [`JwtAuthApi/JwtAuthApi.http`](JwtAuthApi/JwtAuthApi.http) contiene
> todas estas peticiones encadenadas, listas para ejecutar desde Visual Studio o VS Code.

---

## Sobre el refresh token

El sistema usa **dos tokens** con propósitos distintos:

| | Access token | Refresh token |
|---|---|---|
| Formato | JWT firmado (lleva claims) | String opaco aleatorio (32 bytes en hex) |
| Validación | Local, solo verifica la firma | Contra el store (canje atómico `TryConsume`) |
| ¿Revocable? | No (vive hasta expirar) | Sí (logout / rotación) |
| Dónde se usa | Header `Authorization` en cada request | Solo en `/refresh` y `/logout` |
| Duración | Corta (15 min) | Larga (7 días) |

### Rotación de tokens

Cada vez que se usa un refresh token, **queda revocado y se emite uno nuevo**. El canje
es **atómico**: si dos peticiones llegan a la vez con el mismo token, solo una obtiene un
par nuevo. Si alguien presenta un token ya usado (señal de robo), se revocan **todas** las
sesiones del usuario. Esta lógica está en `AuthService.Refresh(...)`.

### Lógica recomendada en el cliente

```
1. Adjuntar el access token a cada request.
2. Si una respuesta es 401:
   a. Llamar a POST /api/auth/refresh con el refresh token.
   b. Si responde 200 → guardar el nuevo par y reintentar la request original.
   c. Si responde 401 → el refresh también caducó: redirigir al login.
```

---

## Configuración

La sección `Jwt` de [`JwtAuthApi/appsettings.json`](JwtAuthApi/appsettings.json)
controla el comportamiento de los tokens:

```json
{
  "Jwt": {
    "Issuer": "JwtAuthApi",
    "Audience": "JwtAuthApiClients",
    "SigningKey": "",  // NO se versiona: variable de entorno Jwt__SigningKey
    "AccessTokenMinutes": 15,
    "RefreshTokenDays": 7,
    "ClockSkewSeconds": 0
  }
}
```

| Clave | Descripción |
|---|---|
| `Issuer` / `Audience` | Emisor y audiencia esperados (claims `iss` / `aud`). |
| `SigningKey` | Clave simétrica de firma. **Debe tener al menos 32 bytes** (HMAC-SHA256). |
| `AccessTokenMinutes` | Tiempo de vida del access token, en minutos. |
| `RefreshTokenDays` | Tiempo de vida del refresh token, en días. |
| `ClockSkewSeconds` | Tolerancia de reloj al validar la expiración (0 = sin tolerancia). |

---

## Consideraciones para producción

Este proyecto es **educativo**. Antes de llevarlo a un entorno real, hay que tener en cuenta:

- **Clave de firma:** nunca en `appsettings.json`. Usar variables de entorno o un
  *secret manager*, con una clave robusta de ≥32 bytes (sin ella la API no arranca fuera
  de `Development`).
- **Persistencia:** los almacenes de `JwtAuthDatos` (`InMemoryUserStore`,
  `InMemoryRefreshTokenStore`, `InMemoryProductStore`) guardan los datos en memoria, por
  lo que **se pierden al reiniciar** y no se comparten entre instancias. En producción se
  reemplazarían por una base de datos (p. ej. Entity Framework Core) implementando las
  mismas interfaces `IUserStore` / `IRefreshTokenStore` / `IProductStore`. Al estar
  aislados en su propia capa, **solo cambia `JwtAuthDatos` y su `AddJwtAuthData()`**; el
  resto de la solución no se entera.
- **Transporte del refresh token:** para clientes web suele entregarse en una cookie
  `HttpOnly` + `Secure` en lugar del cuerpo JSON, para mitigar XSS.
- **HTTPS:** servir siempre sobre TLS.

---

## Stack técnico

- .NET 10 (LTS) / C#
- `Microsoft.IdentityModel.JsonWebTokens` (`JsonWebTokenHandler`: creación/validación de JWT)
- `Microsoft.AspNetCore.Authentication.JwtBearer` (middleware de autenticación)
- `Microsoft.AspNetCore.OpenApi` (OpenAPI nativo) + `Swashbuckle.AspNetCore.SwaggerUI` (visor)
- NUnit 4, bUnit 2 y `Microsoft.AspNetCore.Mvc.Testing` (pruebas)
- Docker / Docker Compose (empaquetado y orquestación de la API y el front)

## Licencia

[MIT](LICENSE).
