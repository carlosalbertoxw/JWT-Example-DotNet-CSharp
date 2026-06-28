using JwtAuth.Models;

namespace JwtAuth.Services
{
    /// <summary>
    /// Resultado de una operación de autenticación. Encapsula el éxito o fallo
    /// sin recurrir a excepciones para el flujo de control esperado.
    /// </summary>
    public class AuthResult
    {
        public bool Succeeded { get; private init; }

        public string? Error { get; private init; }

        public TokenPair? Tokens { get; private init; }

        public static AuthResult Success(TokenPair tokens) => new()
        {
            Succeeded = true,
            Tokens = tokens
        };

        public static AuthResult Failure(string error) => new()
        {
            Succeeded = false,
            Error = error
        };
    }
}
