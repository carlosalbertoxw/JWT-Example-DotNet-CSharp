using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers
{
    /// <summary>
    /// Controlador de ejemplo que simula un recurso de negocio protegido por
    /// JWT. Muestra tres niveles de acceso: público, autenticado y por rol.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        private static readonly string[] Catalog =
            { "Teclado", "Mouse", "Monitor", "Webcam", "Audífonos" };

        /// <summary>Endpoint público: no requiere token.</summary>
        [HttpGet("public")]
        [AllowAnonymous]
        public IActionResult GetPublic()
        {
            return Ok(new { message = "Catálogo público visible para cualquiera.", items = Catalog });
        }

        /// <summary>Endpoint protegido: requiere un access token válido.</summary>
        [HttpGet]
        [Authorize]
        public IActionResult GetAll()
        {
            return Ok(new
            {
                message = $"Hola {User.Identity?.Name}, este es el listado completo.",
                items = Catalog
            });
        }

        /// <summary>Endpoint restringido por rol: solo usuarios con rol Admin.</summary>
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult Create([FromBody] string name)
        {
            return Created($"/api/products/{name}", new { message = $"Producto '{name}' creado (simulado).", name });
        }
    }
}
