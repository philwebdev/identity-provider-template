using Domain.Entities;
using Domain.Enums;
using Infrastracture.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;


namespace Infrastracture.Data;
public static class InitialiserExtensions
{
    public static async Task InitialiseDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();

        var initialiser = scope.ServiceProvider.GetRequiredService<ApplicationDbContextInitialiser>();

        await initialiser.InitialiseAsync();
    }
}

public class ApplicationDbContextInitialiser
{
    private readonly ILogger<ApplicationDbContextInitialiser> _logger;
    private readonly ApplicationDbContext _context;
    private readonly IServiceScopeFactory _scopeFactory;

    public ApplicationDbContextInitialiser(ILogger<ApplicationDbContextInitialiser> logger, ApplicationDbContext context, IServiceScopeFactory scopeFactory)
    {
        _logger = logger;
        _context = context;
        _scopeFactory = scopeFactory;
    }

    public async Task InitialiseAsync()
    {
        try
        {
            await _context.Database.MigrateAsync();
            await SeedAsync(new CancellationToken());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while initialising the database.");
            throw;
        }
    }

    public async Task SeedAsync(CancellationToken cancellationToken)
    {
        try
        {
            await RegisterClients(cancellationToken);
            await RegisterRoles();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred while seeding the database.");
            throw;
        }
    }

    public async Task RegisterClients(CancellationToken cancellationToken)
    {
        var manager = _scopeFactory.CreateScope().ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var configuration = _scopeFactory.CreateScope().ServiceProvider.GetRequiredService<IConfiguration>();

        var openIddictSettings = configuration.GetSection(OpenIddictSettings.OpenIdDictSettingKey)
            .Get<OpenIddictSettings>() ?? new();

        if (openIddictSettings.Clients.Any())
        {
            foreach (var client in openIddictSettings.Clients)
            {
                var openClient = new OpenIddictApplicationDescriptor
                {
                    ClientId = client.ClientId,
                    ClientSecret = client.ClientSecret,
                    ApplicationType = client.Type,
                    ConsentType = client.ConsentType,
                    DisplayName = client.DisplayName,
                    ClientType = client.Type,
                };

                foreach (var redirectUri in client.RedirectUrisArray)
                {
                    openClient.RedirectUris.Add(new Uri(redirectUri));
                }

                foreach (var postLogoutRedirectUri in client.PostLogoutRedirectUrisArray)
                {
                    openClient.PostLogoutRedirectUris.Add(new Uri(postLogoutRedirectUri));
                }

                foreach (var permissions in client.PermissionsArray)
                {
                    openClient.Permissions.Add(permissions);
                }

                foreach (var requirement in client.RequirementsArray)
                {
                    openClient.Requirements.Add(requirement);
                }

                var clientInDb = await manager.FindByClientIdAsync(client.ClientId, cancellationToken);

                if (clientInDb is null)
                {
                    await manager.CreateAsync(openClient!, cancellationToken);
                }
                else
                {
                    await manager.UpdateAsync(clientInDb, openClient, cancellationToken);
                }
            }
        }
    }

    public async Task RegisterRoles()
    {
        var _roleManager = _scopeFactory.CreateScope().ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        bool isNotEnumEmpty = Enum.GetValues(typeof(Roles)).Length > 0;
        if (isNotEnumEmpty)
        {
            foreach (var role in Enum.GetNames<Roles>())
            {
                var roleToAdd = new ApplicationRole { Name = role };
                var resultRole = await _roleManager.FindByNameAsync(roleToAdd.Name);
                if (resultRole is null)
                {
                    await _roleManager.CreateAsync(roleToAdd);
                }
            }
        }
    }
}