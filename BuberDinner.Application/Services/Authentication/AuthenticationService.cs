
using BuberDinner.Application.Common.Interfaces.Authentication;

namespace BuberDinner.Application.Services.Authentication;

public class AuthenticationService : IAuthenticationService
{
    private readonly IJwtTokenGenerator jwtTokenGenerator;

    public AuthenticationService(IJwtTokenGenerator jwtTokenGenerator)
    {
        this.jwtTokenGenerator = jwtTokenGenerator;
    }

    public AuthenticationResult Login(string email, string password)
    {
        return new AuthenticationResult(new Guid(), "firstname", "lastName", email, "token");
    }

    public AuthenticationResult Register(string firstName, string lastName, string email, string password)
    {
        // Check if User already exists

        // Create User (generate unique Id)

        // Generate JWT token 
        var userId = new Guid();
        var token = this.jwtTokenGenerator.GenerateToken(userId, firstName, lastName);

        return new AuthenticationResult(userId, firstName, lastName, email, token);
    }
}