using JwtAuth.Models;

namespace JwtAuth.Stores
{
    /// <summary>
    /// Repositorio de usuarios. En un sistema real estaría respaldado por una
    /// base de datos; aquí se usa una implementación en memoria para el ejemplo.
    /// </summary>
    public interface IUserStore
    {
        AppUser? FindByUsername(string username);

        AppUser? FindById(Guid id);
    }
}
