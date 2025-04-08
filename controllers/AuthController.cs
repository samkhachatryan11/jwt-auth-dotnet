using System.Threading.Tasks;
using DotnetJWTAuth.Models.Dtos;
using DotnetJWTAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetJWTAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ICookieService _cookieService;

        public AuthController(IAuthService authService, ICookieService cookieService)
        {
            _authService = authService;
            _cookieService = cookieService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto registrationDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.RegisterUserAsync(registrationDto);

            if (!result.Success)
            {
                return BadRequest(result);
            }

            _cookieService.SetAuthCookies(Response, result);

            return Ok(
                new
                {
                    message = result.Message,
                    username = result.Username,
                    role = result.Role,
                    expiration = result.Expiration,
                }
            );
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.LoginAsync(loginDto);

            if (!result.Success)
            {
                return Unauthorized(result);
            }

            _cookieService.SetAuthCookies(Response, result);

            return Ok(
                new
                {
                    message = result.Message,
                    username = result.Username,
                    role = result.Role,
                    expiration = result.Expiration,
                }
            );
        }
    }
}
