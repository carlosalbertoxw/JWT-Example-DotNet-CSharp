using JwtAuth.Models;

namespace JwtAuth.Tokens
{
    /// <summary>
    /// Encapsula la emisión de tokens, de forma totalmente independiente de
    /// ASP.NET Core para poder reutilizarse y probarse aislada. La validación la
    /// hace el middleware JwtBearer con <see cref="TokenService.CreateValidationParameters(Configuration.JwtSettings)"/>.
    /// </summary>
    public interface ITokenService
    {
        /// <summary>Crea un access token firmado para el usuario indicado.</summary>
        string CreateAccessToken(AppUser user);

        /// <summary>
        /// Genera un refresh token opaco, criptográficamente aleatorio.
        /// </summary>
        string GenerateRefreshToken();
    }
}
