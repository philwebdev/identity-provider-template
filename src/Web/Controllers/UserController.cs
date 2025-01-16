using Application.Common;
using Application.User.Command;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers;

/// <summary>
/// Controller for handle user
/// </summary>
/// <returns></returns>
public class UserController(IMediator mediator) : Controller
{

    private readonly IMediator _mediator = mediator;

    /// <summary>
    /// Api Registrazione Utente
    /// </summary>
    /// <param name="request">Dati candidato obbligatori</param> 
    /// <returns></returns>
    /// <exception cref="BadHttpRequestException"></exception>
    /// <exception cref="Exception"></exception>
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<BaseResponse> Register([FromBody] RegisterUserDTO request)
    {
        RegisterUserCommand command = new RegisterUserCommand(request);
        return await _mediator.Send(command);
    }
}
