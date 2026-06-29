using System.Collections.Concurrent;
using JwtAuth.Models;
using JwtAuth.Stores;

namespace JwtAuthDatos.Stores
{
    /// <summary>
    /// Implementación en memoria de <see cref="IRefreshTokenStore"/>, apta para
    /// demos y pruebas. En producción se reemplazaría por una persistencia real
    /// (base de datos), conservando el mismo contrato.
    /// </summary>
    public class InMemoryRefreshTokenStore : IRefreshTokenStore
    {
        private readonly ConcurrentDictionary<string, RefreshToken> _tokens = new();

        public void Add(RefreshToken token)
        {
            ArgumentNullException.ThrowIfNull(token);
            _tokens[token.Token] = token;
        }

        public RefreshToken? Find(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            _tokens.TryGetValue(token, out RefreshToken? found);
            return found;
        }

        public bool Revoke(string token)
        {
            if (string.IsNullOrWhiteSpace(token) || !_tokens.TryGetValue(token, out RefreshToken? found))
                return false;

            if (found.RevokedAtUtc is null)
                found.RevokedAtUtc = DateTime.UtcNow;

            return true;
        }

        public void RevokeAllForUser(Guid userId)
        {
            foreach (RefreshToken token in _tokens.Values)
            {
                if (token.UserId == userId && token.RevokedAtUtc is null)
                    token.RevokedAtUtc = DateTime.UtcNow;
            }
        }

        public int RemoveExpired()
        {
            DateTime now = DateTime.UtcNow;
            int removed = 0;

            foreach (KeyValuePair<string, RefreshToken> entry in _tokens)
            {
                // Solo se eliminan los expirados. Un token revocado pero aún no
                // expirado se conserva para poder detectar su reutilización.
                if (entry.Value.ExpiresAtUtc <= now && _tokens.TryRemove(entry.Key, out _))
                    removed++;
            }

            return removed;
        }
    }
}
