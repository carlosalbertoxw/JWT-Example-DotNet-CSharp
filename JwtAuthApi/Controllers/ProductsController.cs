using JwtAuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers
{
    /// <summary>
    /// Controlador de ejemplo que simula un recurso de negocio protegido por
    /// JWT. Muestra tres niveles de acceso: público, autenticado y por rol.
    /// La lógica del catálogo vive en <see cref="IProductService"/>; este
    /// controlador solo traduce entre HTTP y dicho servicio.
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        private readonly IProductService _products;

        public ProductsController(IProductService products)
        {
            _products = products;
        }

        /// <summary>Endpoint público: no requiere token.</summary>
        [HttpGet("public")]
        [AllowAnonymous]
        public IActionResult GetPublic()
        {
            return Ok(new { message = "Catálogo público visible para cualquiera.", items = _products.GetCatalog() });
        }

        /// <summary>Endpoint protegido: requiere un access token válido.</summary>
        [HttpGet]
        [Authorize]
        public IActionResult GetAll()
        {
            return Ok(new
            {
                message = $"Hola {User.Identity?.Name}, este es el listado completo.",
                items = _products.GetCatalog()
            });
        }

        /// <summary>Endpoint restringido por rol: solo usuarios con rol Admin.</summary>
        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult Create([FromBody] string name)
        {
            _products.Create(name);
            return Created($"/api/products/{name}", new { message = $"Producto '{name}' creado.", name });
        }
    }
}
