namespace Infrastracture.Options;

public class OpenIddictSettings
{
    public static string OpenIdDictSettingKey = "OpenIddict";
    public OpenIddictSettingsClient[] Clients { get; set; } = Array.Empty<OpenIddictSettingsClient>();
}


public class OpenIddictSettingsClient
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string ConsentType { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string RedirectUris { get; set; } = string.Empty;
    public string[] RedirectUrisArray
    {
        get
        {
            return RedirectUris.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
        }
    }

    public string PostLogoutRedirectUris { get; set; } = string.Empty;
    public string[] PostLogoutRedirectUrisArray
    {
        get
        {
            return PostLogoutRedirectUris.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
        }
    }
    public string Permissions { get; set; } = string.Empty;
    public string[] PermissionsArray
    {
        get
        {
            return Permissions.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
        }
    }

    public string Requirements { get; set; } = string.Empty;
    public string[] RequirementsArray
    {
        get
        {
            return Requirements.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
        }
    }
    public string Roles { get; set; } = string.Empty;
    public string[] RolesArray
    {
        get
        {
            return Requirements.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
        }
    }

}
