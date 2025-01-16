using FluentValidation.Results;

namespace Application.Common.Exception;

public class ValidationException : System.Exception
{
    public IDictionary<string, string[]> Errors { get; }

    public ValidationException()
        : base("One or more validation failures have occurred.")
    {
        Errors = new Dictionary<string, string[]>();
    }

    public ValidationException(IEnumerable<ValidationFailure> failures)
        : this()
    {
        Errors = (from e in failures
                  group e.ErrorMessage by e.PropertyName).ToDictionary((IGrouping<string, string> failureGroup) => failureGroup.Key, (IGrouping<string, string> failureGroup) => failureGroup.ToArray());
    }
}
