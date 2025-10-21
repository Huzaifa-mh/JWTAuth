using JWTAuth.Data;
using JWTAuth.Entities;
using JWTAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]

    public class AuthController : ControllerBase
    {
        private readonly IConfiguration configuration;
        private readonly string connectionString;
        private readonly DataBaseHelper dataBaseHelper;

        public AuthController(IConfiguration _configuration)
        {
            configuration = _configuration;
            connectionString = _configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Database connection string is missing."); ;
            dataBaseHelper = new DataBaseHelper(_configuration);
        }

        public static User user = new();

        [HttpPost("register")]
        public async Task<ActionResult<User>> RegisterAsync(UserDto request)
        {
            var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

            var newUser = new User
            {
                Id = Guid.NewGuid(),
                Username = request.Username,
                PasswordHash = hashedPassword,
                Role = request.Role
            };
            //Console.WriteLine(connectionString);
            var (isSuccess, errorMessage) = await dataBaseHelper.AddUser(newUser);
            if (!isSuccess)
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
            Console.WriteLine($"Role: {user.Role}");
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        [HttpDelete("delete/{Username}")]
        public async Task<IActionResult> DeleteUser(string Username)
        {
            var result= dataBaseHelper.Delete(Username);
            if (result)
            {
                return Ok(new { message = "Employee Deleted" });
            }
            else
            {
                return BadRequest();
            }
        }

        //Authentication Of Roles 

        [HttpGet("user-only")]
        [Authorize]
        public IActionResult UserOnly()
        {
            return Ok("This endpoint require User Authentication");
        }

        [HttpGet("admin-only")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            return Ok("This endpoint require Admin Authentication");
        }




        private string CreateToken(User user)
        {
            var claims = new List<Claim> {
        //        new Claim(JwtRegisteredClaimNames.Name, user.Username),
        //new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        //new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
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
