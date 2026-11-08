namespace JwtAuth.Stores
{
    /// <summary>
    /// Registro de intentos fallidos para el rate limiting (clave + instante de cada fallo).
    /// </summary>
    public interface IAttemptStore
    {
        void Add(string key, DateTimeOffset at);

        int CountSince(string key, DateTimeOffset since);

        DateTimeOffset? OldestSince(string key, DateTimeOffset since);

        void DeleteKey(string key);

        void PurgeBefore(DateTimeOffset before);
    }
}
