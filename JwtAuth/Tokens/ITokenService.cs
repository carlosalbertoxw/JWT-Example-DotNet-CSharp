using System.Security.Claims;
using JwtAuth.Models;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Tokens
{
    /// <summary>
    /// Encapsula la creación y validación de tokens JWT, de forma totalmente
    /// independiente de ASP.NET Core para poder reutilizarse y probarse aislada.
    /// </summary>
    public interface ITokenService
    {
        /// <summary>
        /// Crea un access token firmado para el usuario indicado.
        /// </summary>
        /// <returns>El token serializado y su fecha de expiración (UTC).</returns>
        (string Token, DateTime ExpiresAtUtc) CreateAccessToken(AppUser user);

        /// <summary>
        /// Genera un refresh token opaco, criptográficamente aleatorio.
        /// </summary>
        string GenerateRefreshToken();

        /// <summary>
        /// Valida un access token y devuelve el <see cref="ClaimsPrincipal"/>
        /// asociado, o null si el token es inválido o expiró.
        /// </summary>
        ClaimsPrincipal? ValidateAccessToken(string token);

        /// <summary>
        /// Devuelve los parámetros de validación usados internamente, para que
        /// la capa de API pueda reutilizarlos al configurar el bearer.
        /// </summary>
        TokenValidationParameters GetValidationParameters();
    }
}
