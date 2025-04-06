using JWTAuth.Data;
using JWTAuth.Entities;
using JWTAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class AuthController: ControllerBase
    {
        private readonly IConfiguration configuration;
        private readonly DataBaseHelper dataBaseHelper;

        public AuthController(IConfiguration _configuration)
        {
            configuration = _configuration;
            dataBaseHelper = new DataBaseHelper(_configuration);
        }

        public static User user = new();

        [Route("api/[controller]/User")]
        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

            var newUser = new User
            {
                Id = Guid.NewGuid(),
                Username = request.Username,
                PasswordHash = hashedPassword
            };
            if(!dataBaseHelper.AddUser(newUser, out string errorMessage))
            {
                return BadRequest(errorMessage);
            }
            else
            {
                return Ok(newUser);
            }

        }

        [HttpGet]
        public ActionResult<User> get()
        {
            return Ok(user);
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto request)
        {
            var user = dataBaseHelper.GetUserNameByUsername(request.Username);
            if (user == null)
            {
                return BadRequest("User Not Found");
            }
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.Username)
            };
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!)
                );

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
