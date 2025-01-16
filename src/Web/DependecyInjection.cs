using FluentValidation;
using Infrastracture.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using OpenIddict.Validation.AspNetCore;
using System.Reflection;
using Web.Options;

namespace WebIDP;
public static class DependencyInjection
{
    public static IServiceCollection AddServiceIdentityProviderServer(this IServiceCollection services, WebApplicationBuilder build)
    {

        services.AddCors(options =>
        {
            options.AddDefaultPolicy(
            policy =>
            {
                policy.AllowAnyHeader().AllowAnyOrigin().AllowAnyMethod();
                //policy.WithOrigins((build.Configuration?.GetValue<string>("Cors:WithOrigins") ?? string.Empty).Split(";"));
            });
        });

        services.AddValidatorsFromAssembly(Assembly.GetExecutingAssembly());

        services.AddHttpContextAccessor();
        services.Configure<IdentityOptions>(options =>
        {
            options.SignIn.RequireConfirmedAccount = false;
            options.SignIn.RequireConfirmedEmail = false;
            options.SignIn.RequireConfirmedPhoneNumber = false;
            options.Password.RequireDigit = false;
            options.Password.RequireLowercase = false;
            options.Password.RequireUppercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequiredLength = 0;
            options.Password.RequiredUniqueChars = 0;
        });

        services.AddControllersWithViews().AddRazorRuntimeCompilation();


        services.AddAuthentication(options =>
        {
            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;


        }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.LoginPath = "/account/login";
        });

        var identityProviderServerProperties = build.Configuration.GetSection("OpenIddict:IdentityProviderProperties").Get<IdentityProviderServerProperties>() ?? new();
        services.AddOpenIddict()
             .AddCore(options =>
             {
                 options.UseEntityFrameworkCore().UseDbContext<ApplicationDbContext>();
             }).AddServer(options =>
             {
                 options.SetAccessTokenLifetime(TimeSpan.FromMinutes(identityProviderServerProperties.AccessTokenLifetime));
                 options.SetIdentityTokenLifetime(
                         TimeSpan.FromMinutes(identityProviderServerProperties.AccessTokenLifetime));
                 options.SetRefreshTokenLifetime(TimeSpan.FromMinutes(identityProviderServerProperties.RefreshTokenLifetime));
                 options.AddEphemeralEncryptionKey()
                        .AddEphemeralSigningKey()
                        .DisableAccessTokenEncryption();

                 options.AllowAuthorizationCodeFlow()
                        .RequireProofKeyForCodeExchange()
                        .AllowClientCredentialsFlow()
                        .AllowRefreshTokenFlow();

                 options.SetAuthorizationEndpointUris(identityProviderServerProperties.AuthorizationEndPoint)
                        .SetIntrospectionEndpointUris(identityProviderServerProperties.AuthorizationIntrospectEndPoint)
                        .SetTokenEndpointUris(identityProviderServerProperties.TokenEndPoint)
                        .SetLogoutEndpointUris(identityProviderServerProperties.LogOutEmdPoint);

                 options.RegisterScopes(identityProviderServerProperties.ScopesArray);
                 options
                     .UseAspNetCore()
                     .DisableTransportSecurityRequirement()
                     .EnableTokenEndpointPassthrough()
                     .EnableAuthorizationEndpointPassthrough()
                     .EnableLogoutEndpointPassthrough();

                 if (!string.IsNullOrWhiteSpace(identityProviderServerProperties.Issuer))
                 {
                     options.SetIssuer(identityProviderServerProperties.Issuer);
                 }

             }).AddValidation(options =>
             {
                 options.SetIssuer(build.Configuration.GetSection("OpenIddict:IdentityProviderProperties:Issuer").Value ?? string.Empty);
                 if (build.Environment.IsDevelopment())
                 {
                     options.UseSystemNetHttp().ConfigureHttpClientHandler((config) =>
                     {
                         config.ServerCertificateCustomValidationCallback += (o, c, ch, er) => true;
                     });
                 }
                 else
                 {
                     options.UseSystemNetHttp();
                 }

                 options.UseLocalServer();
                 options.UseAspNetCore();
             });

        services.AddAuthorization(options =>
        {
            options.AddPolicy("TokenAuth", policy =>
            {
                policy.AuthenticationSchemes.Add(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
                policy.RequireAuthenticatedUser();
            });
        });

        services.AddSwaggerGen(c =>
        {
            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            c.IncludeXmlComments(xmlPath);

            c.AddSecurityDefinition("Bearer",
                new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Please enter into field the word 'Bearer' following by space and JWT",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
                        {
                            {
                                new OpenApiSecurityScheme
                                {
                                    Reference = new OpenApiReference
                                    {
                                        Type = ReferenceType.SecurityScheme,
                                        Id = "Bearer"
                                    }
                                },
                                Array.Empty<string>()
                            }
                        });
        });


        return services;
    }
}