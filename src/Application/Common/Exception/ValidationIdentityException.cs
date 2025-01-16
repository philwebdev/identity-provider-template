using Microsoft.AspNetCore.Identity;

namespace Application.Common.Exception;

public class ValidationIdentityException : System.Exception
{
    public IDictionary<string, string[]> Errors { get; }

    public ValidationIdentityException()
        : base("One or more validation failures have occurred.")
    {
        Errors = new Dictionary<string, string[]>();
    }

    public ValidationIdentityException(IEnumerable<IdentityError> failures)
        : this()
    {
        Errors = (from e in failures
                  group e.Description by e.Code).ToDictionary((IGrouping<string, string> failureGroup) => failureGroup.Key, (IGrouping<string, string> failureGroup) => failureGroup.ToArray());
    }
}