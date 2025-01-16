using Application.Common;
using Application.Common.Interface;
using Domain.Entities;
using Domain.Enums;
using FluentValidation;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace Application.User.Command;

public class RegisterUserCommand(RegisterUserDTO registerUserDto) : IRequest<BaseResponse>
{
    public RegisterUserDTO CommandItem { get; set; } = registerUserDto;
}

public class RegisterUserCommandHandler(IApplicationDbContext context, IValidator<RegisterUserDTO> validator,
                                        UserManager<ApplicationUser> usermananager,
                                        RoleManager<IdentityRole> rolemanager) : IRequestHandler<RegisterUserCommand, BaseResponse>
{

    private readonly IApplicationDbContext _context = context;
    private readonly IValidator<RegisterUserDTO> _validator = validator;
    private readonly UserManager<ApplicationUser> _userManager = usermananager;
    private readonly RoleManager<IdentityRole> _roleManager = rolemanager;

    public async Task<BaseResponse> Handle(RegisterUserCommand request, CancellationToken cancellationToken)
    {
        ApplicationUser newUser = SetDataNewUser(request);

        var result = _validator.Validate(request.CommandItem);

        if (!result.IsValid)
        {
            throw new Common.Exception.ValidationException(result.Errors);
        }

        newUser.CreateData = DateTime.UtcNow;
        var userCreate = await _userManager.CreateAsync(newUser);
        await _userManager.AddPasswordAsync(newUser, request.CommandItem.Password);

        if (!userCreate.Succeeded)
        {
            throw new Common.Exception.ValidationIdentityException(userCreate.Errors);
        }

        await SetRoleUser(newUser);

        var user = await _userManager.FindByEmailAsync(newUser.Email!);

        if (user is not null)
        {
            await _userManager.UpdateAsync(user);
        }
        await _context.SaveChangesAsync(cancellationToken);
        return await Task.FromResult(new BaseResponse(newUser.Id));
    }


    public ApplicationUser SetDataNewUser(RegisterUserCommand request)
    {
        var user = new ApplicationUser
        {
            Name = request.CommandItem.Name,
            UserName = request.CommandItem.Email,
            Surname = request.CommandItem.Surname,
            Email = request.CommandItem.Email,
        };
        return user;
    }

    public async Task SetRoleUser(ApplicationUser user)
    {
        IdentityRole? userRole = await _roleManager.FindByNameAsync(nameof(Roles.USER));
        if (userRole != null && !string.IsNullOrEmpty(userRole.Name))
        {
            await _userManager.AddToRoleAsync(user, userRole.Name);
        }
        else
        {
            throw new ValidationException("Role user not found");
        }
    }
}
