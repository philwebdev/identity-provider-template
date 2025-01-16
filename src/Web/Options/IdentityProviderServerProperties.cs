namespace Web.Options;
public class IdentityProviderServerProperties
{
    public string? Issuer { get; set; } = string.Empty;
    public string AuthorizationEndPoint { get; set; } = string.Empty;
    public string AuthorizationIntrospectEndPoint { get; set; } = string.Empty;
    public string LogOutEmdPoint { get; set; } = string.Empty;
    public string TokenEndPoint { get; set; } = string.Empty;
    public double AccessTokenLifetime { get; set; }
    public double RefreshTokenLifetime { get; set; }
    public string Scopes { get; set; } = string.Empty;
    public string[] ScopesArray => Scopes.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
    public string ResponseType { get; set; } = string.Empty;
    public string[] ResponseTypeArray => ResponseType.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();

    public string Audiances { get; set; } = string.Empty;
    public string[] AudiancesArray => Audiances.Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();

    public string? ValidIssuers { get; set; }
    public string[] ValidIssuersArray => (ValidIssuers ?? string.Empty).Split(";", StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
}

