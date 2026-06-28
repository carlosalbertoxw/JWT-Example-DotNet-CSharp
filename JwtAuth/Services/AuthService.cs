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
        private readonly IUserStore _userStore;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITokenService _tokenService;
        private readonly IRefreshTokenStore _refreshTokenStore;
        private readonly JwtSettings _settings;

        public AuthService(
            IUserStore userStore,
            IPasswordHasher passwordHasher,
            ITokenService tokenService,
            IRefreshTokenStore refreshTokenStore,
            JwtSettings settings)
        {
            _userStore = userStore;
            _passwordHasher = passwordHasher;
            _tokenService = tokenService;
            _refreshTokenStore = refreshTokenStore;
            _settings = settings;
        }

        public AuthResult Login(string username, string password)
        {
            AppUser? user = _userStore.FindByUsername(username);

            // Mensaje genérico para no revelar si el usuario existe o no.
            if (user is null || !_passwordHasher.Verify(password, user.PasswordHash))
                return AuthResult.Failure("Usuario o contraseña inválidos.");

            return AuthResult.Success(IssueTokens(user));
        }

        public AuthResult Refresh(string refreshToken)
        {
            RefreshToken? stored = _refreshTokenStore.Find(refreshToken);

            if (stored is null || !stored.IsActive)
                return AuthResult.Failure("Refresh token inválido o expirado.");

            AppUser? user = _userStore.FindById(stored.UserId);
            if (user is null)
                return AuthResult.Failure("El usuario asociado ya no existe.");

            // Rotación: el refresh token usado se revoca y se emite uno nuevo.
            _refreshTokenStore.Revoke(refreshToken);

            return AuthResult.Success(IssueTokens(user));
        }

        public bool Logout(string refreshToken)
        {
            return _refreshTokenStore.Revoke(refreshToken);
        }

        private TokenPair IssueTokens(AppUser user)
        {
            (string accessToken, DateTime accessExpires) = _tokenService.CreateAccessToken(user);

            string refreshTokenValue = _tokenService.GenerateRefreshToken();
            DateTime refreshExpires = DateTime.UtcNow.AddDays(_settings.RefreshTokenDays);

            _refreshTokenStore.Add(new RefreshToken
            {
                Token = refreshTokenValue,
                UserId = user.Id,
                ExpiresAtUtc = refreshExpires
            });

            return new TokenPair
            {
                AccessToken = accessToken,
                AccessTokenExpiresAtUtc = accessExpires,
                RefreshToken = refreshTokenValue,
                RefreshTokenExpiresAtUtc = refreshExpires
            };
        }
    }
}
