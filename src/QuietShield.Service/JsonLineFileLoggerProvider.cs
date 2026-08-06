using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace QuietShield.Service;

public sealed class JsonLineFileLoggerProvider : ILoggerProvider
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly object _sync = new();
    private readonly string _path;

    public JsonLineFileLoggerProvider(string stateRoot)
    {
        var logDirectory = Path.Combine(Path.GetFullPath(stateRoot), "logs");
        Directory.CreateDirectory(logDirectory);
        _path = Path.Combine(logDirectory, "service.jsonl");
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);
    public void Dispose() { }

    private void Write(string category, LogLevel level, EventId eventId, string message, Exception? exception)
    {
        var line = JsonSerializer.Serialize(new
        {
            timestampUtc = DateTimeOffset.UtcNow,
            level = level.ToString(),
            category,
            eventId = eventId.Id,
            eventName = eventId.Name,
            message,
            exceptionType = exception?.GetType().Name,
            exceptionMessage = exception?.Message
        }, Options);
        lock (_sync) File.AppendAllText(_path, line + Environment.NewLine, System.Text.Encoding.UTF8);
    }

    private sealed class FileLogger : ILogger
    {
        private readonly JsonLineFileLoggerProvider _provider;
        private readonly string _category;
        public FileLogger(JsonLineFileLoggerProvider provider, string category) { _provider = provider; _category = category; }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel)) _provider.Write(_category, logLevel, eventId, formatter(state, exception), exception);
        }
    }
}
