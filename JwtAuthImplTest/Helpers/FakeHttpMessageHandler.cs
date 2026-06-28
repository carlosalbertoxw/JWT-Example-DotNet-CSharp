using System.Net;
using System.Text;

namespace JwtAuthImplTest.Helpers
{
    /// <summary>
    /// Handler HTTP falso que delega cada petición en una función provista por la
    /// prueba. Registra las peticiones recibidas para poder hacer aserciones
    /// (p. ej. sobre el header Authorization).
    /// </summary>
    public class FakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, int, HttpResponseMessage> _responder;
        private int _callCount;

        public List<HttpRequestMessage> Requests { get; } = new();

        /// <param name="responder">
        /// Recibe la petición y el número de llamada (1-based) y devuelve la respuesta.
        /// </param>
        public FakeHttpMessageHandler(Func<HttpRequestMessage, int, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
            : this((req, _) => responder(req))
        {
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _callCount++;
            Requests.Add(request);
            return Task.FromResult(_responder(request, _callCount));
        }

        public static HttpResponseMessage Json(HttpStatusCode status, string json) => new(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        public static HttpResponseMessage Empty(HttpStatusCode status) => new(status);
    }
}
