namespace QuietShield.Core.Results;

public enum OperationStatus
{
    Succeeded,
    NotImplemented,
    Unsupported,
    Failed,
    Cancelled
}

public sealed record OperationResult(OperationStatus Status, string Message)
{
    public bool IsSuccess => Status == OperationStatus.Succeeded;

    public static OperationResult Success(string message = "Completed.") =>
        new(OperationStatus.Succeeded, message);

    public static OperationResult NotImplemented(string message) =>
        new(OperationStatus.NotImplemented, message);

    public static OperationResult Unsupported(string message) =>
        new(OperationStatus.Unsupported, message);

    public static OperationResult Failure(string message) =>
        new(OperationStatus.Failed, message);

    public static OperationResult Cancelled(string message = "Cancelled.") =>
        new(OperationStatus.Cancelled, message);

    public static OperationResult<T> Success<T>(T value, string message = "Completed.") =>
        new(OperationStatus.Succeeded, message, value);

    public static OperationResult<T> NotImplemented<T>(string message) =>
        new(OperationStatus.NotImplemented, message, default);

    public static OperationResult<T> Unsupported<T>(string message) =>
        new(OperationStatus.Unsupported, message, default);

    public static OperationResult<T> Failure<T>(string message) =>
        new(OperationStatus.Failed, message, default);
}

public sealed record OperationResult<T>(OperationStatus Status, string Message, T? Value)
{
    public bool IsSuccess => Status == OperationStatus.Succeeded;
}
