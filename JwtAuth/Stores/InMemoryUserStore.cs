using System.Collections.Concurrent;
using JwtAuth.Models;
using JwtAuth.Security;

namespace JwtAuth.Stores
{
    /// <summary>
    /// Implementación en memoria de <see cref="IUserStore"/>. Se siembra con un
    /// par de usuarios de ejemplo (admin y user) cuyas contraseñas se hashean al
    /// construir el store.
    /// </summary>
    public class InMemoryUserStore : IUserStore
    {
        private readonly ConcurrentDictionary<Guid, AppUser> _byId = new();
        private readonly ConcurrentDictionary<string, AppUser> _byUsername =
            new(StringComparer.OrdinalIgnoreCase);

        public InMemoryUserStore(IPasswordHasher passwordHasher)
        {
            ArgumentNullException.ThrowIfNull(passwordHasher);

            Seed(new AppUser
            {
                Username = "admin",
                PasswordHash = passwordHasher.Hash("Admin123!"),
                Roles = new[] { "Admin", "User" }
            });

            Seed(new AppUser
            {
                Username = "user",
                PasswordHash = passwordHasher.Hash("User123!"),
                Roles = new[] { "User" }
            });
        }

        private void Seed(AppUser user)
        {
            _byId[user.Id] = user;
            _byUsername[user.Username] = user;
        }

        public AppUser? FindByUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return null;

            _byUsername.TryGetValue(username, out AppUser? user);
            return user;
        }

        public AppUser? FindById(Guid id)
        {
            _byId.TryGetValue(id, out AppUser? user);
            return user;
        }
    }
}
