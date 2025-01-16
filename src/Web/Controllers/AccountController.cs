using Domain.Entities;
using Infrastracture.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Web.Models;
using Web.Utilities;

namespace Web.Controllers;

/// <summary>
/// Controller for handle login 
/// </summary>
/// <returns></returns>
[Route("/[controller]")]
public class AccountController(ILogger<AccountController> logger, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManagaer, IConfiguration configuration) : Controller
{
    private readonly ILogger<AccountController> _logger = logger;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly SignInManager<ApplicationUser> _signInManager = signInManagaer;
    private readonly IConfiguration _configuration = configuration;
    /// <summary>
    /// API to get view Login 
    /// </summary>
    /// <returns></returns>
    [HttpGet("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        return View("Login");
    }


    /// <summary>
    /// Api Login User 
    /// </summary>
    /// <param name="model">Login data</param>
    /// <returns></returns>
    [HttpPost("login")]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        // Extract client ID from return URL if present, otherwise empty string
        string clientId = string.IsNullOrEmpty(model.ReturnUrl) ? string.Empty : StringHelper.GetClientIdStringUri(model.ReturnUrl);

        // Set return URL in ViewData, defaulting to home if not specified
        ViewData["ReturnUrl"] = model.ReturnUrl ?? Url.Content("~/");

        if (model.ReturnUrl is not null && !string.IsNullOrEmpty(model.ReturnUrl))
        {
            // Get OpenIddict settings from configuration
            var openIddictSettings = _configuration.GetSection(OpenIddictSettings.OpenIdDictSettingKey).Get<OpenIddictSettings>() ?? new();

            // Find client settings matching the client ID
            OpenIddictSettingsClient? client = openIddictSettings.Clients.FirstOrDefault(it => it.ClientId == clientId);
            if (client is null)
            {
                return View(model);
            }

            // Validate model state
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Find user by email
            var user = await _userManager.FindByNameAsync(model.Email);
            if (user is null)
            {
                ModelState.AddModelError(string.Empty, "Password o username wrong");
                return View(model);
            }

            // Get user roles
            var rolesUser = await _userManager.GetRolesAsync(user);

            // Attempt to sign in user with password
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                // Create claims for authenticated user
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Name ?? string.Empty),
                    new Claim(ClaimTypes.NameIdentifier, user.Id)
                };

                // Add role claims
                foreach (string roleUser in rolesUser)
                {
                    claims.Add(new Claim(ClaimTypes.Role, roleUser));
                }

                // Log claims for debugging
                _logger.LogInformation(System.Text.Json.JsonSerializer.Serialize(claims));

                // Create claims identity and sign in user
                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));

                _logger.LogInformation("User logged in");
                return LocalRedirect(model.ReturnUrl);
            }
            else
            {
                // Add error if login failed
                ModelState.AddModelError(string.Empty, "Password or username wrong");
                return View(model);
            }
        }

        throw new Exception("Return null is empty");
    }

}

