using System.Security.Claims;
using JwtAuth.Models;
using JwtAuth.Services;
using JwtAuthApi.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace JwtAuthApi.Controllers
{
    /// <summary>
    /// Endpoints de autenticación: login, refresh, logout y consulta del
    /// usuario autenticado. Toda la lógica JWT vive en el proyecto JwtAuth;
    /// este controlador solo traduce entre HTTP y la librería.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        /// <summary>Valida credenciales y devuelve un par de tokens.</summary>
        [HttpPost("login")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            AuthResult result = _authService.Login(request.Username, request.Password);

            if (!result.Succeeded)
                return Unauthorized(new { error = result.Error });

            return Ok(ToResponse(result.Tokens!));
        }

        /// <summary>Renueva el par de tokens a partir de un refresh token válido.</summary>
        [HttpPost("refresh")]
        [AllowAnonymous]
        [EnableRateLimiting("auth")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Refresh([FromBody] RefreshRequest request)
        {
            AuthResult result = _authService.Refresh(request.RefreshToken);

            if (!result.Succeeded)
                return Unauthorized(new { error = result.Error });

            return Ok(ToResponse(result.Tokens!));
        }

        /// <summary>Revoca el refresh token indicado (cierre de sesión).</summary>
        [HttpPost("logout")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Logout([FromBody] RefreshRequest request)
        {
            string? sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(sub, out Guid userId))
                return Unauthorized();

            // Respuesta idempotente: 204 exista o no el token. No se distingue el
            // caso "no existe" del "no es tuyo" para no filtrar validez de tokens.
            _authService.Logout(request.RefreshToken, userId);

            return NoContent();
        }

        /// <summary>Devuelve la información del usuario autenticado (claims del token).</summary>
        [HttpGet("me")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public IActionResult Me()
        {
            return Ok(new
            {
                userId = User.FindFirstValue(ClaimTypes.NameIdentifier),
                username = User.Identity?.Name ?? User.FindFirstValue("username"),
                roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray()
            });
        }

        private static AuthResponse ToResponse(TokenPair tokens) => new()
        {
            AccessToken = tokens.AccessToken,
            AccessTokenExpiresAtUtc = tokens.AccessTokenExpiresAtUtc,
            RefreshToken = tokens.RefreshToken,
            RefreshTokenExpiresAtUtc = tokens.RefreshTokenExpiresAtUtc
        };
    }
}
