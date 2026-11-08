using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using JwtAuth.Models;
using JwtAuth.Stores;

namespace JwtAuthDatos.Stores
{
    /// <summary>
    /// Implementación en memoria de <see cref="IRefreshTokenStore"/>, apta para
    /// demos y pruebas. Indexa por el hash SHA-256 del token: el valor en claro
    /// nunca se guarda, igual que haría una tabla en base de datos.
    /// </summary>
    public class InMemoryRefreshTokenStore : IRefreshTokenStore
    {
        private readonly ConcurrentDictionary<string, RefreshToken> _tokens = new();

        public void Add(string token, Guid userId, DateTime expiresAtUtc)
        {
            _tokens[Hash(token)] = new RefreshToken
            {
                UserId = userId,
                ExpiresAtUtc = expiresAtUtc
            };
        }

        public RefreshToken? Find(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            _tokens.TryGetValue(Hash(token), out RefreshToken? found);
            return found;
        }

        public bool TryConsume(string token, DateTime nowUtc)
        {
            RefreshToken? found = Find(token);
            if (found is null)
                return false;

            // El lock por token hace atómico "comprobar y revocar": solo una
            // petición puede pasar de vigente a revocado.
            lock (found)
            {
                if (found.IsRevoked || found.IsExpired(nowUtc))
                    return false;

                found.RevokedAtUtc = nowUtc;
                return true;
            }
        }

        public bool Revoke(string token, DateTime nowUtc)
        {
            RefreshToken? found = Find(token);
            if (found is null)
                return false;

            lock (found)
            {
                found.RevokedAtUtc ??= nowUtc;
            }
            return true;
        }

        public void RevokeAllForUser(Guid userId, DateTime nowUtc)
        {
            foreach (RefreshToken token in _tokens.Values.Where(t => t.UserId == userId))
            {
                lock (token)
                {
                    token.RevokedAtUtc ??= nowUtc;
                }
            }
        }

        public int RemoveExpired(DateTime nowUtc)
        {
            int removed = 0;

            foreach (KeyValuePair<string, RefreshToken> entry in _tokens)
            {
                // Solo se eliminan los expirados. Un token revocado pero aún no
                // expirado se conserva para poder detectar su reutilización.
                if (entry.Value.IsExpired(nowUtc) && _tokens.TryRemove(entry.Key, out _))
                    removed++;
            }

            return removed;
        }

        private static string Hash(string token) =>
            Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }
}
