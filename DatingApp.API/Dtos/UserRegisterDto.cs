using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.Dtos
{
    public class UserRegisterDto
    {
        public string Username { get; set; }
        [StringLength(8, MinimumLength = 4, ErrorMessage="Password length error")]
        public string Password { get; set; }
    }
}