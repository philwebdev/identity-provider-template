using Microsoft.AspNetCore.Identity;

namespace Domain.Entities;
public class ApplicationUser : IdentityUser
{
    public string? Name { get; set; }
    public string? Surname { get; set; }
    public bool PrivacyPolicy { get; set; }
    public string? ResetToken { get; set; }
    public string? EmailToken { get; set; }
    public string? EmailChange { get; set; }
    public DateTime? TokenEmailTimeValidation { get; set; }
    public DateTime? TokenPasswordTimeValidation { get; set; }
    public DateTime? CreateData { get; set; }

}

