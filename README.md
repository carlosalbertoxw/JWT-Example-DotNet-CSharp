# JWT-Example-DotNet-CSharp

Ejemplo de autenticación basada en **JWT (JSON Web Tokens)** con **.NET 8 / C#**, que
muestra un flujo completo de *login*, *refresh token con rotación*, *logout* y acceso
a endpoints protegidos por autenticación y por rol.

La solución está dividida en proyectos para separar responsabilidades en capas:
la **validación/emisión de JWT**, el **acceso a datos** y la **capa web** quedan
**desacoplados** y se pueden probar de forma aislada. Incluye además un cliente
**Blazor** que consume la API.

---

## Estructura de la solución

```
JWT-Example-DotNet-CSharp/
├── JwtAuth/                → Librería de validación/emisión JWT (sin dependencia de ASP.NET Core)
├── JwtAuthDatos/           → Capa de datos: almacenes de usuarios, refresh tokens y productos
├── JwtAuthApi/             → Web API que expone los endpoints de autenticación y ejemplos
├── JwtAuthTest/            → Pruebas unitarias (NUnit) de JwtAuth y JwtAuthDatos
├── JwtAuthImpl/            → Implementación cliente de JWT (consumo de la API), desacoplada del front
├── JwtAuthImplFront/        → App Blazor (Interactive Server): solo la UI, referencia a JwtAuthImpl
└── JwtAuthImplTest/        → Pruebas (NUnit + bUnit) de la implementación cliente y los componentes
```

### Capas y dependencias (backend)

```
JwtAuthApi ──► JwtAuth        (validación/emisión: contratos IUserStore / IRefreshTokenStore)
     │
     └───────► JwtAuthDatos ──► JwtAuth   (implementa los contratos + almacén de productos)
```

`JwtAuth` define **qué** se necesita (interfaces) pero no **cómo** se persiste;
`JwtAuthDatos` aporta las implementaciones. Así, cambiar a una base de datos real
no toca la lógica de validación: basta con sustituir la capa de datos.

### `JwtAuth` — validación/emisión JWT (class library)

Contiene **solo la lógica de validación y emisión de tokens**, más los **contratos**
(interfaces) de los almacenes. No conoce cómo se persisten los datos.

| Archivo | Responsabilidad |
|---|---|
| `Configuration/JwtSettings.cs` | Parámetros de configuración: issuer, audience, clave de firma, tiempos de vida. |
| `Models/AppUser.cs` | Usuario de la aplicación (id, username, hash de contraseña, roles). |
| `Models/RefreshToken.cs` | Refresh token persistido, con propiedad `IsActive` (no revocado y no expirado). |
| `Models/TokenPair.cs` | Par emitido en login/refresh: access token + refresh token con sus expiraciones. |
| `Security/IPasswordHasher.cs` + `Pbkdf2PasswordHasher.cs` | Hashing de contraseñas con PBKDF2-SHA256 (salt aleatorio, comparación en tiempo constante). |
| `Tokens/ITokenService.cs` + `TokenService.cs` | Creación y validación de access tokens (HMAC-SHA256) y generación de refresh tokens. |
| `Stores/IUserStore.cs` | **Contrato** del repositorio de usuarios (la implementación vive en `JwtAuthDatos`). |
| `Stores/IRefreshTokenStore.cs` | **Contrato** del almacén de refresh tokens con soporte de revocación. |
| `Services/IAuthService.cs` + `AuthService.cs` | Orquesta login, refresh (con rotación) y logout. Devuelve `AuthResult`. |
| `Extensions/ServiceCollectionExtensions.cs` | `AddJwtAuth(...)`: registra la validación/emisión en DI. **No registra los almacenes** (eso lo hace `JwtAuthDatos`). |

> La librería **no referencia ASP.NET Core**. Solo depende de
> `System.IdentityModel.Tokens.Jwt`, `Microsoft.IdentityModel.Tokens` y
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
| `Stores/InMemoryRefreshTokenStore.cs` | Implementa `IRefreshTokenStore` (alta, búsqueda, revocación, purga de expirados). |
| `Stores/IProductStore.cs` + `InMemoryProductStore.cs` | Almacén del catálogo de productos (contenido de ejemplo, ajeno a JWT). |
| `Extensions/ServiceCollectionExtensions.cs` | `AddJwtAuthData()`: registra los tres almacenes en DI. **Único punto a cambiar para apuntar a una BD real.** |

### `JwtAuthApi` — Web API

| Archivo | Responsabilidad |
|---|---|
| `Program.cs` | Registra la validación JWT (`AddJwtAuth`) y la capa de datos (`AddJwtAuthData`); configura el bearer JWT (reutilizando los `TokenValidationParameters` del `TokenService`), la autorización, los controladores y Swagger con botón **Authorize**. |
| `Contracts/AuthContracts.cs` | DTOs de entrada/salida: `LoginRequest`, `RefreshRequest`, `AuthResponse`. |
| `Controllers/AuthController.cs` | Endpoints `login`, `refresh`, `logout` y `me`. Solo traduce entre HTTP y `IAuthService`. |
| `Controllers/ProductsController.cs` | Recurso de ejemplo con tres niveles de acceso (público, autenticado y por rol). Delega la lógica en `IProductService`. |
| `Services/IProductService.cs` + `ProductService.cs` | Lógica del catálogo de productos (ajena a JWT); se apoya en `IProductStore` de la capa de datos. |

> La lógica de **autenticación** (`AuthController`/`IAuthService`) y la de **productos**
> (`ProductsController`/`IProductService`) están separadas en clases distintas: los
> productos son solo contenido de ejemplo y no se mezclan con el flujo JWT.

### `JwtAuthTest` — pruebas unitarias (NUnit)

30 pruebas que cubren el hasher de contraseñas, el `TokenService`, el
`InMemoryRefreshTokenStore` (de `JwtAuthDatos`) y el `AuthService` (login, rotación de
refresh, logout).

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
| `Components/Pages/Login.razor` | Formulario de inicio de sesión. |
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
- Al ser **Blazor Server**, las llamadas a la API salen desde el servidor (no desde el
  navegador), por lo que **no requiere configuración CORS** en la API.

### `JwtAuthImplTest` — pruebas del cliente y los componentes

26 pruebas con **NUnit** y **bUnit** sobre `JwtAuthImpl` y los componentes del front.
Para no depender de JS interop, `TokenStore` se abstrae con `ITokenStore` y se sustituye
por uno en memoria; las llamadas HTTP se simulan con un `FakeHttpMessageHandler`.

| Área | Qué cubre |
|---|---|
| `JwtParserTests` | Extracción de claims (username, roles) y detección de expiración. |
| `AuthApiClientTests` | Login (éxito y fallo) y logout que limpia el store. |
| `ProductsApiClientTests` | Catálogo público (sin token), bearer en endpoints protegidos, **401 → refresh → reintento** y código HTTP al crear. |
| `JwtAuthenticationStateProviderTests` | Anónimo sin token, principal con nombre/roles, refresco al expirar, limpieza si el refresh falla. |
| `Components/NavMenuTests` | Enlaces según estado de sesión (login vs. usuario + logout) y catálogo público. |
| `Components/ProductsTests` | Redirección al login si anónimo; sección "crear" solo con rol `Admin`. |
| `Components/LoginTests` | Envío del formulario: navegación en éxito, mensaje de error en fallo. |

```bash
dotnet test JwtAuthImplTest/JwtAuthImplTest.csproj
```

---

## Cómo ejecutar

Requisitos: **.NET 8 SDK**.

```bash
# Restaurar y compilar toda la solución
dotnet build JwtAuthApi/JwtAuthApi.sln

# Ejecutar las pruebas unitarias
dotnet test JwtAuthApi/JwtAuthApi.sln

# Levantar la API (Swagger se abre en la raíz en modo Development)
dotnet run --project JwtAuthApi/JwtAuthApi.csproj
```

Por defecto la API queda escuchando en `http://localhost:5274` y
`https://localhost:7036` (ver `JwtAuthApi/Properties/launchSettings.json`).
La UI de Swagger queda disponible en `/swagger`.

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

### Usuarios de ejemplo

| Usuario | Contraseña | Roles |
|---|---|---|
| `admin` | `Admin123!` | `Admin`, `User` |
| `user`  | `User123!`  | `User` |

---

## Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| `POST` | `/api/auth/login`   | Pública | Valida credenciales y devuelve un par de tokens. |
| `POST` | `/api/auth/refresh` | Pública | Renueva el par de tokens a partir de un refresh token válido (rota el anterior). |
| `POST` | `/api/auth/logout`  | Bearer  | Revoca el refresh token indicado. |
| `GET`  | `/api/auth/me`      | Bearer  | Devuelve los claims del usuario autenticado. |
| `GET`  | `/api/products/public` | Pública | Catálogo visible para cualquiera. |
| `GET`  | `/api/products`     | Bearer  | Listado completo (requiere token válido). |
| `POST` | `/api/products`     | Rol `Admin` | Crea un producto (lo agrega al catálogo en memoria). |

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
  "accessToken": "eyJhbGc...",
  "accessTokenExpiresAtUtc": "2026-06-27T20:51:00Z",
  "refreshToken": "h8Kf...base64...",
  "refreshTokenExpiresAtUtc": "2026-07-04T20:36:00Z",
  "tokenType": "Bearer"
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

{ "refreshToken": "h8Kf...base64..." }
```

Devuelve un **par nuevo** (access + refresh). Se reemplazan ambos en el cliente.

### 4. Logout

Revoca el refresh token para que no pueda volver a usarse:

```http
POST /api/auth/logout
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{ "refreshToken": "h8Kf...base64..." }
```

> El archivo [`JwtAuthApi/JwtAuthApi.http`](JwtAuthApi/JwtAuthApi.http) contiene
> todas estas peticiones encadenadas, listas para ejecutar desde Visual Studio o VS Code.

---

## Sobre el refresh token

El sistema usa **dos tokens** con propósitos distintos:

| | Access token | Refresh token |
|---|---|---|
| Formato | JWT firmado (lleva claims) | String opaco aleatorio (64 bytes) |
| Validación | Local, solo verifica la firma | Contra el store (`Find` + `IsActive`) |
| ¿Revocable? | No (vive hasta expirar) | Sí (logout / rotación) |
| Dónde se usa | Header `Authorization` en cada request | Solo en `/refresh` y `/logout` |
| Duración | Corta (15 min) | Larga (7 días) |

### Rotación de tokens

Cada vez que se usa un refresh token, **queda revocado y se emite uno nuevo**.
Si un refresh token robado se utiliza, el del usuario legítimo dejará de funcionar,
lo que permite detectar el robo. Esta lógica está en `AuthService.Refresh(...)`.

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
    "SigningKey": "clave-super-secreta-de-ejemplo-cambiar-en-produccion-1234567890",
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

- **Clave de firma:** no dejarla en `appsettings.json`. Usar *user secrets*, variables
  de entorno o un *secret manager*, y una clave robusta de ≥32 bytes.
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

- .NET 8 / C#
- `System.IdentityModel.Tokens.Jwt` + `Microsoft.IdentityModel.Tokens` (creación/validación de JWT)
- `Microsoft.AspNetCore.Authentication.JwtBearer` (middleware de autenticación)
- `Swashbuckle.AspNetCore` (Swagger / OpenAPI)
- NUnit (pruebas unitarias)
