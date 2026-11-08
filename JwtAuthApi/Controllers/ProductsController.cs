using JwtAuthApi.Contracts;
using JwtAuthDatos.Models;
using JwtAuthDatos.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers
{
    /// <summary>
    /// Controlador de ejemplo que simula un recurso de negocio protegido por
    /// JWT. Muestra tres niveles de acceso: público (sin precio), autenticado
    /// (con precio) y por rol (alta de productos, solo Admin).
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        private readonly IProductStore _products;

        public ProductsController(IProductStore products)
        {
            _products = products;
        }

        /// <summary>Endpoint público: todos los productos, pero sin el precio.</summary>
        [HttpGet("public")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(IEnumerable<PublicProduct>), StatusCodes.Status200OK)]
        public IEnumerable<PublicProduct> GetPublic() =>
            _products.GetAll().Select(p => new PublicProduct(p.Id, p.Name, p.Description));

        /// <summary>Endpoint protegido: requiere un access token válido (incluye el precio).</summary>
        [HttpGet]
        [Authorize]
        [ProducesResponseType(typeof(IEnumerable<Product>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        public IReadOnlyList<Product> GetAll() => _products.GetAll();

        /// <summary>Endpoint restringido por rol: solo usuarios con rol Admin.</summary>
        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ProducesResponseType(typeof(Product), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        public IActionResult Create([FromBody] CreateProductRequest request)
        {
            Product product = _products.Add(
                request.Name.Trim(), request.Description?.Trim() ?? string.Empty, request.Price!.Value);
            return StatusCode(StatusCodes.Status201Created, product);
        }
    }
}
