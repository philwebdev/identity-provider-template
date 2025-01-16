using Domain.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Web.Controllers;

public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public AuthorizationController(
     IOpenIddictApplicationManager applicationManager,
     IOpenIddictAuthorizationManager authorizationManager,
     IOpenIddictScopeManager scopeManager,
     SignInManager<ApplicationUser> signInManager,
     UserManager<ApplicationUser> userManager)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    #region CONNECT_TOKEN

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> ExchangeAsync()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            return await ExchangeAuthorizationCodeAsync();
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private async Task<IActionResult> ExchangeAuthorizationCodeAsync()
    {
        var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        string? claimsPrincipal = authResult?.Principal?.GetClaim(Claims.Subject);
        if (!string.IsNullOrEmpty(claimsPrincipal))
        {
            var user = await _userManager.FindByIdAsync(claimsPrincipal);
            if (user == null)
            {
                return Forbid(Errors.InvalidGrant, "The token is no longer valid.");
            }

            if (!await _signInManager.CanSignInAsync(user))
            {
                return Forbid(Errors.InvalidGrant, "The user is no longer allowed to sign in.");
            }
            var identity = await CreateIdentityAsync(user);

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("Claims principal not found");
    }

    private async Task<ClaimsIdentity> CreateIdentityAsync(ApplicationUser user)
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, user.Name)
                .SetClaim(Claims.FamilyName, user.Surname);

        var roles = await _userManager.GetRolesAsync(user);
        identity.SetClaims(Claims.Role, roles.ToImmutableArray());

        identity.SetDestinations(GetDestinations);

        return identity;
    }

    /// <summary>
    /// Determines the destination of a given claim within OpenIddict tokens.
    /// </summary>
    /// <param name="claim">The claim to be processed.</param>
    /// <returns>
    /// An IEnumerable of strings specifying whether the claim should be included in
    /// the access token, the identity token, both, or excluded, based on the claim's type and scopes.
    /// </returns>
    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;

                if (claim.Subject is not null && (claim.Subject.HasScope(Scopes.Profile) || claim.Subject.HasScope(Claims.Name)))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.FamilyName:
                yield return Destinations.AccessToken;

                if (claim.Subject is not null && (claim.Subject.HasScope(Scopes.Profile) || claim.Subject.HasScope(Claims.FamilyName)))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject is not null && (claim.Subject.HasScope(Scopes.Profile) || claim.Subject.HasScope(Claims.Email)))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (claim.Subject is not null && (claim.Subject.HasScope(Scopes.Profile) || claim.Subject.HasScope(Claims.Role)))
                    yield return Destinations.IdentityToken;

                yield break;

            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
    #endregion

    #region CONNECT_AUTHORIZE



    /// <summary>
    /// Flow authorize login
    /// </summary>
    [ApiExplorerSettings(IgnoreApi = true)]
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        // Gets the OpenID Connect request from the HTTP context
        // If it cannot be retrieved, throws an exception
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("Impossibile recuperare la richiesta OpenID Connect.");

        // Authenticates the current user
        var result = await HttpContext.AuthenticateAsync();

        // If authentication fails or login redirect is needed,
        // handles the authentication failure
        if (result == null || !result.Succeeded || ShouldRedirectToLogin(request, result))
        {
            return HandleAuthenticationFailure(request);
        }

        // Retrieves the authenticated user details
        var user = await GetUserOrFail(result.Principal);

        // Retrieves the client application details
        var application = await GetApplicationOrFail(request.ClientId!);

        // Gets valid authorizations for the user and application
        var authorizations = await GetValidAuthorizations(user, application, request);

        // Generates token or handles user consent
        return await GenerateTokenOrHandleConsent(request, user, application, authorizations);
    }

    /// <summary>
    /// Gets the user from the claims principal or throws an exception if not found
    /// </summary>
    /// <param name="principal">The claims principal containing user info</param>
    /// <returns>The ApplicationUser if found</returns>
    /// <exception cref="InvalidOperationException">Thrown if user cannot be retrieved</exception>
    private async Task<ApplicationUser> GetUserOrFail(ClaimsPrincipal principal)
    {
        var user = await _userManager.GetUserAsync(principal);
        if (user == null)
        {
            throw new InvalidOperationException("Impossibile recuperare i dettagli dell'utente.");
        }
        return user;
    }

    /// <summary>
    /// Gets the client application by ID or throws an exception if not found
    /// </summary>
    /// <param name="clientId">The client application ID</param>
    /// <returns>The application object if found</returns>
    /// <exception cref="InvalidOperationException">Thrown if application cannot be retrieved</exception>
    private async Task<object> GetApplicationOrFail(string clientId)
    {
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            throw new InvalidOperationException("Impossibile recuperare i dettagli dell'applicazione client.");
        }
        return application;
    }

    /// <summary>
    /// Gets valid authorizations for the user and application
    /// </summary>
    /// <param name="user">The application user</param>
    /// <param name="application">The client application</param>
    /// <param name="request">The OpenID Connect request</param>
    /// <returns>List of valid authorizations</returns>
    /// <exception cref="InvalidOperationException">Thrown if client ID not found</exception>
    private async Task<List<object>> GetValidAuthorizations(ApplicationUser user, object application, OpenIddictRequest request)
    {
        string? applicationId = await _applicationManager.GetIdAsync(application);
        if (!string.IsNullOrEmpty(applicationId))
        {
            return await _authorizationManager.FindAsync(
                subject: await _userManager.GetUserIdAsync(user),
                client: applicationId,
                status: Statuses.Valid,
                type: AuthorizationTypes.Permanent,
                scopes: request.GetScopes()).ToListAsync();
        }
        throw new InvalidOperationException("Client id not found");
    }

    /// <summary>
    /// Determines if user should be redirected to login page
    /// </summary>
    /// <param name="request">The OpenID Connect request</param>
    /// <param name="result">The authentication result</param>
    /// <returns>True if redirect needed, false otherwise</returns>
    private bool ShouldRedirectToLogin(OpenIddictRequest request, AuthenticateResult result)
    {
        return request.HasPrompt(Prompts.Login) ||
               (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
                DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value));
    }

    /// <summary>
    /// Handles failed authentication by either forbidding access or challenging for credentials
    /// </summary>
    /// <param name="request">The OpenID Connect request</param>
    /// <returns>Appropriate IActionResult based on authentication state</returns>
    private IActionResult HandleAuthenticationFailure(OpenIddictRequest request)
    {
        if (request.HasPrompt(Prompts.None))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User not auth."
                }!));
        }

        var prompt = string.Join(" ", request.GetPrompts().Remove(Prompts.Login));
        var parameters = GetPromptParameters(request, prompt);

        return Challenge(authenticationSchemes: IdentityConstants.ApplicationScheme,
            properties: new AuthenticationProperties { RedirectUri = Request.PathBase + Request.Path + QueryString.Create(parameters) });
    }

    /// <summary>
    /// Gets parameters for the prompt, excluding the prompt parameter itself
    /// </summary>
    /// <param name="request">The OpenID Connect request</param>
    /// <param name="prompt">The prompt value</param>
    /// <returns>List of key-value pairs representing parameters</returns>
    private List<KeyValuePair<string, StringValues>> GetPromptParameters(OpenIddictRequest request, string prompt)
    {
        var parameters = Request.HasFormContentType ?
            Request.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList() :
            Request.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();
        parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));
        return parameters;
    }

    /// <summary>
    /// Generates token or handles user consent based on authorization state
    /// </summary>
    /// <param name="request">The OpenID Connect request</param>
    /// <param name="user">The application user</param>
    /// <param name="application">The client application</param>
    /// <param name="authorizations">List of valid authorizations</param>
    /// <returns>IActionResult based on consent and authorization state</returns>
    private async Task<IActionResult> GenerateTokenOrHandleConsent(OpenIddictRequest request, ApplicationUser user,
                                                                 object application, List<object> authorizations)
    {
        switch (await GetConsentType(application, authorizations))
        {
            case ConsentTypes.External when !authorizations.Any():
                return Forbid(authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "User not authorized to use this application"
                    }!));
            default:
                var identity = await CreateClaimsIdentity(user, request);

                return SignInWithIdentity(identity);
        }
    }

    /// <summary>
    /// Gets the consent type for the application and authorizations
    /// </summary>
    /// <param name="application">The client application</param>
    /// <param name="authorizations">List of valid authorizations</param>
    /// <returns>The consent type string</returns>
    /// <exception cref="InvalidOperationException">Thrown if consent type missing</exception>
    private async Task<string> GetConsentType(object application, List<object> authorizations)
    {
        string? consentType = string.Empty;
        if (authorizations.Any())
        {
            return ConsentTypes.Implicit;
        }
        consentType = await _applicationManager.GetConsentTypeAsync(application);
        return consentType ?? throw new InvalidOperationException("Consent type missing"); ;

    }

    /// <summary>
    /// Creates a claims identity for the user with appropriate claims and scopes
    /// </summary>
    /// <param name="user">The application user</param>
    /// <param name="request">The OpenID Connect request</param>
    /// <returns>ClaimsIdentity populated with user claims and scopes</returns>
    private async Task<ClaimsIdentity> CreateClaimsIdentity(ApplicationUser user, OpenIddictRequest request)
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType,
                    Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, user.Name)
                .SetClaim(Claims.FamilyName, user.Surname)
                .SetClaims(Claims.Role, (await _userManager.GetRolesAsync(user)).ToImmutableArray());
        identity.AddClaims(await _userManager.GetClaimsAsync(user));
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());
        return identity;
    }

    /// <summary>
    /// Signs in the user with the provided claims identity
    /// </summary>
    /// <param name="identity">The claims identity for the user</param>
    /// <returns>SignIn action result</returns>
    private IActionResult SignInWithIdentity(ClaimsIdentity identity)
    {
        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
    #endregion

    #region LOGOUT

    // Endpoint for handling logout requests via both POST and GET methods
    // POST requires antiforgery token validation while GET ignores it
    [HttpPost("~/connect/logout"), ValidateAntiForgeryToken]
    [HttpGet("~/connect/logout"), IgnoreAntiforgeryToken]
    public async Task<IActionResult> Logout()
    {
        // Ask ASP.NET Core Identity to delete the local and external cookies created
        // when the user agent is redirected from the external identity provider
        // after a successful authentication flow 
        await _signInManager.SignOutAsync();
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties if none was set.
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }
    #endregion

    #region INTROSPECT

    // Endpoint for token introspection - allows checking if a token is active/valid
    [HttpPost("~/connect/introspect")]
    public async Task<IActionResult> Introspect()
    {
        // Attempt to authenticate the request using OpenIddict's authentication scheme
        var response = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // If authentication succeeded, return that the token is active
        if (response.Succeeded)
        {
            return Ok(new
            {
                active = true,
            });
        }
        // If authentication failed, return that the token is not active
        return Ok(new
        {
            active = false
        });
    }
    #endregion
}
