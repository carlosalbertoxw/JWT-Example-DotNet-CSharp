using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace JwtAuthImpl.Auth
{
    /// <summary>
    /// Proveedor de estado de autenticación para Blazor. Construye el
    /// <see cref="ClaimsPrincipal"/> a partir del access token almacenado y,
    /// si éste expiró, intenta renovarlo con el refresh token.
    /// </summary>
    public class JwtAuthenticationStateProvider : AuthenticationStateProvider
    {
        private static readonly AuthenticationState Anonymous =
            new(new ClaimsPrincipal(new ClaimsIdentity()));

        private readonly ITokenStore _tokenStore;
        private readonly AuthApiClient _apiClient;

        public JwtAuthenticationStateProvider(ITokenStore tokenStore, AuthApiClient apiClient)
        {
            _tokenStore = tokenStore;
            _apiClient = apiClient;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            string? accessToken = await _tokenStore.GetAccessTokenAsync();
            if (string.IsNullOrEmpty(accessToken))
                return Anonymous;

            if (JwtParser.IsExpired(accessToken))
            {
                // El access token expiró: se intenta renovar con el refresh token.
                if (await _apiClient.TryRefreshAsync())
                    accessToken = await _tokenStore.GetAccessTokenAsync();
                else
                {
                    await _tokenStore.ClearAsync();
                    return Anonymous;
                }
            }

            return string.IsNullOrEmpty(accessToken)
                ? Anonymous
                : new AuthenticationState(BuildPrincipal(accessToken));
        }

        /// <summary>
        /// Re-evalúa el estado y notifica a la UI. Debe llamarse tras un login
        /// o logout para que los componentes se actualicen.
        /// </summary>
        public async Task NotifyAuthenticationChangedAsync()
        {
            AuthenticationState state = await GetAuthenticationStateAsync();
            NotifyAuthenticationStateChanged(Task.FromResult(state));
        }

        private static ClaimsPrincipal BuildPrincipal(string accessToken)
        {
            // El nombre se toma del claim "username". Los roles se serializan con
            // la URI estándar de .NET (ClaimTypes.Role), así que se usa ese tipo
            // para que AuthorizeView/IsInRole funcionen correctamente.
            var identity = new ClaimsIdentity(
                JwtParser.ParseClaimsFromJwt(accessToken),
                authenticationType: "jwt",
                nameType: "username",
                roleType: ClaimTypes.Role);

            return new ClaimsPrincipal(identity);
        }
    }
}
