namespace JwtAuth.Services
{
    /// <summary>
    /// Fachada de alto nivel para el flujo de autenticación: inicio de sesión,
    /// renovación de tokens y cierre de sesión.
    /// </summary>
    public interface IAuthService
    {
        /// <summary>Valida credenciales y emite un nuevo par de tokens.</summary>
        AuthResult Login(string username, string password);

        /// <summary>
        /// Renueva el par de tokens a partir de un refresh token válido,
        /// rotando (revocando) el refresh token anterior. Si se presenta un
        /// refresh token ya revocado (reutilización), revoca toda la familia de
        /// tokens del usuario como medida contra robo de tokens.
        /// </summary>
        AuthResult Refresh(string refreshToken);

        /// <summary>
        /// Revoca el refresh token indicado (cierre de sesión), siempre que
        /// pertenezca al usuario <paramref name="userId"/>. Devuelve false si el
        /// token no existe o no es de ese usuario.
        /// </summary>
        /// <remarks>
        /// El access token ya emitido NO se invalida aquí: por la naturaleza
        /// stateless de JWT sigue siendo válido hasta su expiración. Lo mitiga su
        /// tiempo de vida corto. Para un corte inmediato haría falta una
        /// deny-list de identificadores de token (jti).
        /// </remarks>
        bool Logout(string refreshToken, Guid userId);
    }
}
