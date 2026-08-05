namespace QuietShield.Core.Validation;

public sealed record ValidationResult(IReadOnlyList<string> Errors)
{
    public bool IsValid => Errors.Count == 0;

    public static ValidationResult Valid { get; } = new(Array.Empty<string>());

    public static ValidationResult From(params string[] errors) =>
        new(errors.Where(static error => !string.IsNullOrWhiteSpace(error)).ToArray());
}
