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
        /// canjeándolo de forma atómica (rotación). Si se presenta un refresh
        /// token ya usado (reutilización), revoca toda la familia de tokens del
        /// usuario como medida contra robo de tokens.
        /// </summary>
        AuthResult Refresh(string refreshToken);

        /// <summary>
        /// Revoca el refresh token indicado: cierra solo esa sesión (las de otros
        /// dispositivos siguen activas). Si no existe, no hace nada.
        /// </summary>
        /// <remarks>
        /// El access token ya emitido NO se invalida aquí: por la naturaleza
        /// stateless de JWT sigue siendo válido hasta su expiración. Lo mitiga su
        /// tiempo de vida corto. Para un corte inmediato haría falta una
        /// deny-list de identificadores de token (jti).
        /// </remarks>
        void Logout(string refreshToken);
    }
}
