using System.Threading.Tasks;
using JwtAuth.Models;
using JwtAuth.Models.Dtos;

namespace JwtAuth.Services
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterUserAsync(UserRegistrationDto userDto);
        Task<AuthResponse> LoginAsync(LoginDto loginDto);
        Task<User> GetUserByUsernameAsync(string username);
    }
}
