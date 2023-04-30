using Host.AngularAuth.Context;
using Host.AngularAuth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

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


    }
}
