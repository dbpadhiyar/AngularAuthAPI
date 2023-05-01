using Host.AngularAuth.Context;
using Host.AngularAuth.Helper;
using Host.AngularAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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

            var user = _appDbContext.Users.FirstOrDefault(x => x.UserName == userObj.UserName && x.Password== userObj.Password);
            if(user == null)
                return NotFound(new {Message ="User Not Found!"});

            return Ok(new
            {
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

    }
}
