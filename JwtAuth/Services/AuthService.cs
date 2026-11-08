using JwtAuth.Configuration;
using JwtAuth.Models;
using JwtAuth.Security;
using JwtAuth.Stores;
using JwtAuth.Tokens;

namespace JwtAuth.Services
{
    /// <summary>
    /// Implementación de <see cref="IAuthService"/>. Coordina el store de
    /// usuarios, el hasher de contraseñas, el servicio de tokens y el store de
    /// refresh tokens para ofrecer un flujo de autenticación completo.
    /// </summary>
    public class AuthService : IAuthService
    {
        private const string InvalidRefresh = "Refresh token inválido, expirado o revocado.";

        private readonly IUserStore _userStore;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITokenService _tokenService;
        private readonly IRefreshTokenStore _refreshTokenStore;
        private readonly JwtSettings _settings;
        private readonly TimeProvider _time;

        public AuthService(
            IUserStore userStore,
            IPasswordHasher passwordHasher,
            ITokenService tokenService,
            IRefreshTokenStore refreshTokenStore,
            JwtSettings settings,
            TimeProvider time)
        {
            _userStore = userStore;
            _passwordHasher = passwordHasher;
            _tokenService = tokenService;
            _refreshTokenStore = refreshTokenStore;
            _settings = settings;
            _time = time;
        }

        public AuthResult Login(string username, string password)
        {
            AppUser? user = _userStore.FindByUsername(username);

            // Verificar SIEMPRE contra un hash (el del usuario o el señuelo) para
            // que el tiempo de respuesta no revele si el usuario existe.
            bool valid = _passwordHasher.Verify(password, user?.PasswordHash ?? _passwordHasher.DecoyHash);

            // Mensaje genérico para no revelar si el usuario existe o no.
            if (user is null || !valid)
                return AuthResult.Failure("Usuario o contraseña inválidos.");

            return AuthResult.Success(IssueTokens(user));
        }

        public AuthResult Refresh(string refreshToken)
        {
            DateTime now = Now();

            // Canje atómico: comprobar y revocar en una sola operación. Con un
            // "Find + IsActive + Revoke" en pasos separados, dos peticiones
            // simultáneas con el mismo token obtendrían dos pares válidos.
            if (!_refreshTokenStore.TryConsume(refreshToken, now))
            {
                // Detección de reutilización: el token existe pero ya fue usado,
                // señal clásica de robo + replay. Se revoca toda la familia de
                // refresh tokens del usuario para expulsar también al atacante.
                RefreshToken? stored = _refreshTokenStore.Find(refreshToken);
                if (stored is { IsRevoked: true })
                    _refreshTokenStore.RevokeAllForUser(stored.UserId, now);

                return AuthResult.Failure(InvalidRefresh);
            }

            RefreshToken consumed = _refreshTokenStore.Find(refreshToken)!;
            AppUser? user = _userStore.FindById(consumed.UserId);
            if (user is null)
                return AuthResult.Failure(InvalidRefresh);

            return AuthResult.Success(IssueTokens(user));
        }

        public void Logout(string refreshToken) => _refreshTokenStore.Revoke(refreshToken, Now());

        private TokenPair IssueTokens(AppUser user)
        {
            DateTime now = Now();
            string accessToken = _tokenService.CreateAccessToken(user);
            string refreshTokenValue = _tokenService.GenerateRefreshToken();

            _refreshTokenStore.Add(refreshTokenValue, user.Id, now.AddDays(_settings.RefreshTokenDays));

            return new TokenPair
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                ExpiresInSeconds = _settings.AccessTokenMinutes * 60
            };
        }

        private DateTime Now() => _time.GetUtcNow().UtcDateTime;
    }
}
