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
        /// rotando (revocando) el refresh token anterior.
        /// </summary>
        AuthResult Refresh(string refreshToken);

        /// <summary>Revoca un refresh token (cierre de sesión).</summary>
        bool Logout(string refreshToken);
    }
}
