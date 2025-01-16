using System.ComponentModel.DataAnnotations;

namespace Web.Models;

public class LoginViewModel
{
    [Required(ErrorMessage = "Email is mandatory")]
    [EmailAddress(ErrorMessage = "Insert a valid email")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is mandatory.")]
    [RegularExpression(@"^(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{8,}$", ErrorMessage = "Password doesn't meet security requirements")]
    public string Password { get; set; } = string.Empty;
    public string ReturnUrl { get; set; } = string.Empty;
}
