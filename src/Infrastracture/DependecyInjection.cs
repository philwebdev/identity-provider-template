using Application.Common.Interface;
using Domain.Entities;
using Infrastracture.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Infrastracture;
public static class DependencyInjection
{
    public static IServiceCollection AddServiceInfrastracture(this IServiceCollection services, WebApplicationBuilder build)
    {
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            Console.WriteLine("Connection string: " + build.Configuration.GetConnectionString("DefaultConnection"));
            var connectionString = build.Configuration.GetConnectionString("DefaultConnection");
            options.UseNpgsql(connectionString);
            options.UseOpenIddict();

        });

        services.AddIdentity<ApplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<ApplicationDbContext>()
        .AddDefaultTokenProviders();


        services.AddScoped<IApplicationDbContext>(provider => provider.GetRequiredService<ApplicationDbContext>());
        services.AddScoped<ApplicationDbContextInitialiser>();

        return services;
    }
}
