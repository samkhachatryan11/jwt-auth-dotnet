using System.Threading.Tasks;
using DotnetJWTAuth.Models;
using DotnetJWTAuth.Models.Dtos;

namespace DotnetJWTAuth.Services
{
    public interface IAuthService
    {
        Task<AuthResponse> RegisterUserAsync(UserRegistrationDto userDto);
        Task<AuthResponse> LoginAsync(LoginDto loginDto);
        Task<User> GetUserByUsernameAsync(string username);
    }
}
