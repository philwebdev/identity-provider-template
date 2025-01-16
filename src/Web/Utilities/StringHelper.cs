namespace Web.Utilities;

public class StringHelper
{
    public static string GetClientIdStringUri(string returnUrl)
    {
        string clientId = returnUrl?.Split('?')[1]
                                    ?.Split('&')
                                    .Select(param => param.Split('='))
                                    .FirstOrDefault(keyValue => keyValue.Length == 2 && keyValue[0] == "client_id")?[1] ?? string.Empty;

        return clientId;
    }
}

