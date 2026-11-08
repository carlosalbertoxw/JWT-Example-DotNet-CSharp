using JwtAuth.Models;

namespace JwtAuth.Stores
{
    /// <summary>
    /// Almacén de refresh tokens. Recibe el valor en claro, pero las
    /// implementaciones deben guardar solo su hash (como haría una tabla en
    /// base de datos).
    /// </summary>
    public interface IRefreshTokenStore
    {
        void Add(string token, Guid userId, DateTime expiresAtUtc);

        RefreshToken? Find(string token);

        /// <summary>
        /// Canjea el token: lo revoca SOLO si seguía vigente y devuelve si fue
        /// esta llamada la que lo hizo. Debe ser atómico: si dos peticiones
        /// llegan a la vez con el mismo token, solo una puede obtener true.
        /// </summary>
        bool TryConsume(string token, DateTime nowUtc);

        /// <summary>Marca el token como revocado. Devuelve false si no existe.</summary>
        bool Revoke(string token, DateTime nowUtc);

        /// <summary>Revoca todos los refresh tokens activos de un usuario.</summary>
        void RevokeAllForUser(Guid userId, DateTime nowUtc);

        /// <summary>
        /// Elimina los tokens ya expirados para evitar que el almacén crezca sin
        /// límite. Conserva los revocados aún no expirados, pues siguen siendo
        /// necesarios para la detección de reutilización. Devuelve cuántos quitó.
        /// </summary>
        int RemoveExpired(DateTime nowUtc);
    }
}
