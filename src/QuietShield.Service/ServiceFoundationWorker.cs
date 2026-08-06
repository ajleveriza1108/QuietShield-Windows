using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public sealed class ServiceFoundationWorker : BackgroundService
{
    private readonly PersistentServiceRuntime _runtime;
    private readonly IHeartbeatDelay _delay;

    public ServiceFoundationWorker(PersistentServiceRuntime runtime, IHeartbeatDelay delay)
    {
        _runtime = runtime;
        _delay = delay;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await _runtime.StartAsync(stoppingToken).ConfigureAwait(false);
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await _runtime.RecordHeartbeatAsync(stoppingToken).ConfigureAwait(false);
                await _delay.WaitAsync(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        await _runtime.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}

public sealed class ServiceIpcWorker : BackgroundService
{
    private readonly NamedPipeQuietShieldServer _server;
    public ServiceIpcWorker(NamedPipeQuietShieldServer server) => _server = server;
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _server.RunAsync(stoppingToken);
}

public sealed class DiagnosticDurationWorker : BackgroundService
{
    private readonly DiagnosticServiceOptions _options;
    private readonly IHostApplicationLifetime _lifetime;
    public DiagnosticDurationWorker(DiagnosticServiceOptions options, IHostApplicationLifetime lifetime)
    {
        _options = options;
        _lifetime = lifetime;
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(_options.Duration, stoppingToken).ConfigureAwait(false);
        _lifetime.StopApplication();
    }
}
