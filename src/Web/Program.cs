using Application;
using Infrastracture;
using Infrastracture.Data;
using WebIDP;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddApplicationServices();
builder.Services.AddServiceInfrastracture(builder);
builder.Services.AddServiceIdentityProviderServer(builder);
builder.Services.AddControllersWithViews();
var app = builder.Build();


if (app.Environment.IsDevelopment())
{
    await app.InitialiseDatabaseAsync();
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "API V1");
        c.RoutePrefix = string.Empty; // Imposta Swagger come pagina iniziale
    });
}

app.UseStaticFiles();
app.UseRouting();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.UseExceptionHandler(options => { });

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Account}/{action=Login}/{id?}");
});

app.UseHttpsRedirection();


app.Run();

public partial class Program { }
