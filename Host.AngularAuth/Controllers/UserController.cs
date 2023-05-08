using Host.AngularAuth.Context;
using Host.AngularAuth.Helper;
using Host.AngularAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace Host.AngularAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {

        private readonly AppDbContext _appDbContext;

        public UserController(AppDbContext appDbContext)
        {
            _appDbContext= appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if(userObj == null)
                return BadRequest();

            var user = _appDbContext.Users.FirstOrDefault(x => x.UserName == userObj.UserName);
            if(user == null)
                return NotFound(new {Message ="User Not Found!"});

            if(!PasswordHasher.PasswordVerified(userObj.Password,user.Password))
                    return BadRequest(new { Message = "Password is incorrect!" });

            user.Token = CreateJWT(user);
            return Ok(new
            {
                Token = user.Token,
                Message = "Login Success!"
            });                
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null)
                return BadRequest();

            //Check UserName
            if (await CheckUserNameExistAsync(userObj.UserName)) 
                return BadRequest(new { message = "UserName Already Exist" });

            //Check Email
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new {message = "Email Already Exist" });

            //Check Password Stregth
            var password = CheckPasswordStrenth(userObj.Password);
            if (!string.IsNullOrEmpty(password)) 
                return BadRequest(new {message = password.ToString()});

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            if(string.IsNullOrEmpty(userObj.Role))
            { 
                userObj.Role = "User"; 
            }
            else if(userObj.Role != "Admin" || userObj.Role == "User")
            {
                userObj.Role = "User";
            }
            userObj.Token= "";
            await _appDbContext.Users.AddAsync(userObj);
            await _appDbContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "User Registered!"
            }) ;
        }

        [Authorize]
        [HttpGet("GetAllUser")]
        [ProducesResponseType(typeof(IEnumerable<User>),(int)HttpStatusCode.OK)]
        public async Task<IActionResult> GetAllUsers()
        {
            return Ok(await _appDbContext.Users.ToListAsync());
        }

        private async Task<bool> CheckUserNameExistAsync(string userName)
                => await _appDbContext.Users.AnyAsync(a => a.UserName == userName);
        private async Task<bool> CheckEmailExistAsync(string email)
                => await _appDbContext.Users.AnyAsync(a => a.Email == email);

        private string CheckPasswordStrenth(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(string.IsNullOrEmpty(password) || password.Length < 8) 
                sb.Append("Minimumn password length is 8"+Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password Should be Alphanumeric" +Environment.NewLine);
            if (!Regex.IsMatch(password, "[@,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password Must Contain Special Character" + Environment.NewLine);
            return sb.ToString();
        }

        private string CreateJWT(User UserObj)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("Dbpadhiyar30101997.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,UserObj.Role),
                new Claim(ClaimTypes.Name,$"{UserObj.FirstName} {UserObj.LastName}")
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddMinutes(59),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);   
        }

    }
}
