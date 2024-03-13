using BaseLibrary.DTOs;
using BaseLibrary.Responses;

namespace ServerLibrary.Repositories.Contracts
{
    public interface IUserAccount
    {
        Task<GeneralResponse> CreateAsync(Register regiserUser);
        Task<LoginResponse> SigInAsync(Login loginUser);
    }
}
