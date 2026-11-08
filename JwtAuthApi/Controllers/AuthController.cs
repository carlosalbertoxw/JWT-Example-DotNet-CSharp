using JwtAuth.Security;
using JwtAuth.Services;
using JwtAuth.Tokens;
using JwtAuthApi.Contracts;
using JwtAuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers
{
    /// <summary>
    /// Endpoints de autenticación: login, refresh, logout y consulta del
    /// usuario autenticado. Toda la lógica JWT vive en el proyecto JwtAuth;
    /// este controlador solo traduce entre HTTP y la librería. Login y refresh
    /// responden 429 con Retry-After tras varios intentos fallidos.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly AuthRateLimits _limits;

        public AuthController(IAuthService authService, AuthRateLimits limits)
        {
            _authService = authService;
            _limits = limits;
        }

        /// <summary>Valida credenciales y devuelve un par de tokens.</summary>
        [HttpPost("login")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // Dos contadores de fallos:
            //  - por cuenta: frena la fuerza bruta contra un usuario aunque el atacante rote de IP;
            //  - por IP: frena el "password spraying" (una contraseña contra muchas cuentas).
            string accountKey = "login:user:" + request.Username.ToLowerInvariant();
            string ipKey = "login:ip:" + ClientIp();
            if (TooMany(_limits.Account, accountKey) is { } blockedAccount) return blockedAccount;
            if (TooMany(_limits.Ip, ipKey) is { } blockedIp) return blockedIp;

            AuthResult result = _authService.Login(request.Username, request.Password);
            if (!result.Succeeded)
            {
                _limits.Account.RecordFailure(accountKey);
                _limits.Ip.RecordFailure(ipKey);
                return Unauthorized(new ErrorResponse(result.Error!));
            }

            // Solo se limpia el contador de la cuenta: si se limpiara el de la IP,
            // un atacante con una cuenta propia podría reiniciarlo a voluntad.
            _limits.Account.Clear(accountKey);
            return Ok(ToResponse(result));
        }

        /// <summary>Renueva el par de tokens a partir de un refresh token válido.</summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status429TooManyRequests)]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            // Límite por IP para impedir adivinar refresh tokens. No se limpia tras
            // un éxito: si no, un atacante con un token propio podría reiniciarlo.
            string ipKey = "refresh:ip:" + ClientIp();
            if (TooMany(_limits.Ip, ipKey) is { } blocked) return blocked;

            AuthResult result = _authService.Refresh(request.RefreshToken);
            if (!result.Succeeded)
            {
                _limits.Ip.RecordFailure(ipKey);
                return Unauthorized(new ErrorResponse(result.Error!));
            }

            return Ok(ToResponse(result));
        }

        /// <summary>
        /// Revoca el refresh token enviado y cierra solo esa sesión. Es público:
        /// quien tiene el refresh token ya puede usarlo, así que poseerlo basta
        /// para revocarlo, y el cliente no necesita un access token vigente (ni
        /// renovarlo) para salir. Responde 200 aunque el token no exista, para no
        /// revelar su validez.
        /// </summary>
        [HttpPost("logout")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(MessageResponse), StatusCodes.Status200OK)]
        public IActionResult Logout([FromBody] RefreshRequest request)
        {
            _authService.Logout(request.RefreshToken);
            return Ok(new MessageResponse("Sesión cerrada"));
        }

        /// <summary>Devuelve la información del usuario autenticado (claims del token).</summary>
        [HttpGet("me")]
        [Authorize]
        [ProducesResponseType(typeof(MeResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        public IActionResult Me()
        {
            _ = long.TryParse(User.FindFirst("exp")?.Value, out long exp);
            return Ok(new MeResponse(
                User.FindFirst("sub")?.Value,
                User.FindFirst(TokenService.UsernameClaim)?.Value,
                User.FindFirst(TokenService.RoleClaim)?.Value,
                exp));
        }

        private static TokenResponse ToResponse(AuthResult result) =>
            new(result.Tokens!.AccessToken, result.Tokens.RefreshToken, result.Tokens.ExpiresInSeconds);

        private string ClientIp() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "desconocida";

        /// <summary>Respuesta 429 con Retry-After si la clave agotó sus intentos; null si no.</summary>
        private ObjectResult? TooMany(RateLimiter limiter, string key)
        {
            if (!limiter.TooManyAttempts(key))
                return null;

            Response.Headers.RetryAfter = limiter.RetryAfterSeconds(key).ToString();
            return StatusCode(StatusCodes.Status429TooManyRequests,
                new ErrorResponse("Demasiados intentos; espera antes de reintentar"));
        }
    }
}
