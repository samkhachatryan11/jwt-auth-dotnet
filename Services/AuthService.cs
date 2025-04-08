using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DotnetJWTAuth.Data;
using DotnetJWTAuth.Models;
using DotnetJWTAuth.Models.Dtos;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using BC = BCrypt.Net.BCrypt;

namespace DotnetJWTAuth.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _dbContext;
        private readonly JwtSettings _jwtSettings;

        public AuthService(AppDbContext dbContext, IOptions<JwtSettings> jwtSettings)
        {
            _dbContext = dbContext;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task<AuthResponse> RegisterUserAsync(UserRegistrationDto userDto)
        {
            if (await _dbContext.Users.AnyAsync(u => u.Username == userDto.Username))
            {
                return new AuthResponse { Success = false, Message = "Username already exists" };
            }

            if (await _dbContext.Users.AnyAsync(u => u.Email == userDto.Email))
            {
                return new AuthResponse { Success = false, Message = "Email already registered" };
            }

            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = userDto.Username,
                Email = userDto.Email,
                FirstName = userDto.FirstName,
                LastName = userDto.LastName,
                PasswordHash = BC.HashPassword(userDto.Password),
            };

            await _dbContext.Users.AddAsync(user);
            await _dbContext.SaveChangesAsync();

            var token = GenerateJwtToken(user, _jwtSettings.ExpirationInMinutes);
            var refreshToken = GenerateJwtToken(user, _jwtSettings.RefreshExpirationInMinutes);

            return new AuthResponse
            {
                Success = true,
                Token = token,
                RefreshToken = refreshToken,
                Message = "Registration successful",
                Username = user.Username,
                Role = user.Role,
                Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
            };
        }

        public async Task<AuthResponse> LoginAsync(LoginDto loginDto)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(u =>
                u.Username == loginDto.Username
            );

            if (user == null || !BC.Verify(loginDto.Password, user.PasswordHash))
            {
                return new AuthResponse
                {
                    Success = false,
                    Message = "Invalid username or password",
                };
            }

            user.LastLogin = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync();

            var token = GenerateJwtToken(user, _jwtSettings.ExpirationInMinutes);
            var refreshToken = GenerateJwtToken(user, _jwtSettings.RefreshExpirationInMinutes);

            return new AuthResponse
            {
                Success = true,
                Token = token,
                RefreshToken = refreshToken,
                Message = "Login successful",
                Username = user.Username,
                Role = user.Role,
                Expiration = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpirationInMinutes),
            };
        }

        public async Task<User> GetUserByUsernameAsync(string username)
        {
            return await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == username);
        }

        private string GenerateJwtToken(User user, int expiration)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(expiration),
                SigningCredentials = credentials,
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}
