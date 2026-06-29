using JwtAuth.Models;

namespace JwtAuth.Stores
{
    /// <summary>
    /// Almacén de refresh tokens. Permite emitir, recuperar y revocar tokens.
    /// </summary>
    public interface IRefreshTokenStore
    {
        void Add(RefreshToken token);

        RefreshToken? Find(string token);

        /// <summary>Marca el token como revocado. Devuelve false si no existe.</summary>
        bool Revoke(string token);

        /// <summary>Revoca todos los refresh tokens activos de un usuario.</summary>
        void RevokeAllForUser(Guid userId);

        /// <summary>
        /// Elimina los tokens ya expirados para evitar que el almacén crezca sin
        /// límite. Conserva los revocados aún no expirados, pues siguen siendo
        /// necesarios para la detección de reutilización. Devuelve cuántos quitó.
        /// </summary>
        int RemoveExpired();
    }
}
