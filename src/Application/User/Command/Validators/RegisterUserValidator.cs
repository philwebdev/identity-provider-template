using FluentValidation;

namespace Application.User.Command.Validators;

public class RegisterUserValidator : AbstractValidator<RegisterUserDTO>
{

    public RegisterUserValidator()
    {
        RuleFor(x => x.Name).NotEmpty().WithMessage("Field name is mandatory");
        RuleFor(x => x.Surname).NotEmpty().WithMessage("Field Surnamename is mandatory");

        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress()
            .WithMessage("Field email wrong");

    }
}