using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{

    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext context;
        public AuthRepository(DataContext context)
        {
            this.context = context;

        }
        public async Task<User> Login(string username, string password)
        {
            var user = await this.context.Users.FirstOrDefaultAsync(x => x.Username == username);

            if (user == null)
                return null;
            if (!VerifyPassword(password, user.PasswordHash, user.PasswordSalt))
                return null;
            return user;
        }

        private bool VerifyPassword(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computeHash.Length; i++)
                {
                    if (computeHash[i] != passwordHash[i])
                        return false;
                }
            }
            return true;
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwodHash, passwordSalt;
            CreatePasswordHash(password, out passwodHash, out passwordSalt);
            user.PasswordHash = passwodHash;
            user.PasswordSalt = passwordSalt;
            await this.context.Users.AddAsync(user);
            await this.context.SaveChangesAsync();

            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwodHash, out byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwodHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public async Task<bool> UserExists(string username)
        {
            if (await context.Users.AnyAsync(x => x.Username == username))
                return true;
            return false;
        }
    }
}