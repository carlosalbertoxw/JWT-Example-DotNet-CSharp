using System.Collections.Concurrent;
using JwtAuth.Models;

namespace JwtAuth.Stores
{
    /// <summary>
    /// Implementación en memoria de <see cref="IRefreshTokenStore"/>, apta para
    /// demos y pruebas. En producción se reemplazaría por una persistencia real.
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
    }
}
