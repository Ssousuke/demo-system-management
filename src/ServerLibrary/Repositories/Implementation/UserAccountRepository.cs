using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ServerLibrary.Repositories.Implementation
{
    public class UserAccountRepository(IOptions<JwtSection> config, AppDbContext context) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register regiserUser)
        {
            if (regiserUser == null) return new GeneralResponse(false, "Model is empty");
            var checkUser = await FindUserByEmail(regiserUser.Email!);
            if (checkUser != null) return new GeneralResponse(false, "User registed already");

            // Save user
            var applicationUser = await AddToDatabase(new ApplicationUser()
            {
                Name = regiserUser.FullName,
                Email = regiserUser.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(regiserUser.Password)
            });

            // Check, Create and Assign role
            var checkAdminRole = await context.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabase(new SystemRole()
                {
                    Name = Constants.Admin
                });

                await AddToDatabase(new UserRole()
                {
                    RoleId = createAdminRole.Id,
                    UserId = applicationUser.Id,
                });

                return new GeneralResponse(true, "Account Created!");
            }

            var checkUserRole = await context.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkUserRole is null)
            {
                response = await AddToDatabase(new SystemRole()
                {
                    Name = Constants.Admin
                });

                await AddToDatabase(new UserRole()
                {
                    Id = response.Id,
                    UserId = applicationUser.Id
                });
            }
            else await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
            return new GeneralResponse(true, "Account Created!");
        }

        public async Task<LoginResponse> SigInAsync(Login loginUser)
        {
            if (loginUser is null) return new LoginResponse(false, "Model is empty");
            var applicationUser = await FindUserByEmail(loginUser.Email);
            if (applicationUser is null) return new LoginResponse(false, "User not found");

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(loginUser.Password, applicationUser.Password))
                return new LoginResponse(false, "Email or Password not valid");

            var getUserRole = await context.UserRoles.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
            if (getUserRole is null) return new LoginResponse(false, "user role not found");

            var getRoleName = await context.SystemRoles.FirstOrDefaultAsync(_ => _.Id == getUserRole.RoleId);
            if (getRoleName is null) return new LoginResponse(false, "user role not found");

            string jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
            string refreshToken = GenerateRefreshToken();
            return new LoginResponse(Flag: true, Message: "Login successfully", Token: jwtToken, RefreshToken: refreshToken);
        }

        private async Task<ApplicationUser> FindUserByEmail(string email)
            => await context.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));


        private async Task<T> AddToDatabase<T>(T model)
        {
            var result = context.Add(model!);
            await context.SaveChangesAsync();
            return (T)result.Entity;
        }

        private string GenerateToken(ApplicationUser user, string role)
        {
            var secutiryToken = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credentials = new SigningCredentials(secutiryToken, SecurityAlgorithms.HmacSha256);

            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Name!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role!)
            };

            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddMinutes(45),
                signingCredentials: credentials
            );


            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
    }
}
