// SCM-compatible Windows Service entry point. DRAFT/HOLD: NEVER INSTALL IN PRODUCTION.
// No TPM, credentials, authority, import, or replay-resistant native state.
// A named-pipe user boundary is not proof of an authorized caller.
using System.ServiceProcess;

namespace Palaco.Bluetooth.NativeHost;

internal sealed class PalacoDiagnosticService : ServiceBase
{
    private CancellationTokenSource? _stop;
    private Task? _serverTask;

    public PalacoDiagnosticService()
    {
        ServiceName = "PALACO-BT-Diagnostic-HOLD";
        CanStop = true;
        CanPauseAndContinue = false;
        CanShutdown = true;
        AutoLog = false;
    }

    protected override void OnStart(string[] args)
    {
        // Startup never issues privileges and never enables transfers.
        if (_stop is not null)
            throw new InvalidOperationException("Service already started");
        // Fail closed if SCM has not provisioned the expected service SID.
        // No installation or service SID provisioning is done by this program.
        if (!WindowsClientIdentityGate.HasExpectedServiceSid())
            throw new InvalidOperationException("Unverified Windows service SID: HOLD");
        // A synchronous startup preflight prevents SCM from reporting RUNNING
        // when the protected pipe ACL cannot even be constructed.
        using (var preflight = WindowsPipeSecurity.CreateDiagnosticPipe())
        {
            if (preflight is null)
                throw new InvalidOperationException("Windows pipe ACL unavailable: HOLD");
        }
        _stop = new CancellationTokenSource();
        _serverTask = Task.Run(() => Program.RunServerAsync(_stop.Token));
        WindowsWorkerSupervisor.Observe(_serverTask, _stop.Token, code =>
        {
            // Fixed incident category only; no request payload, token or SID logged.
            Console.Error.WriteLine("PALACO-BT-SERVICE-INCIDENT:" + code
                + ":HOLD:DENY");
            try
            {
                // Unexpected worker exit must not leave SCM RUNNING without a
                // listener. No automatic worker restart is performed.
                Stop();
            }
            catch (Exception)
            {
                // If SCM cannot stop, terminate rather than remain apparently
                // healthy with a dead diagnostic worker.
                Environment.FailFast("PALACO-BT-SERVICE-INCIDENT:SCM_STOP_FAILED:HOLD:DENY");
            }
        });
    }

    protected override void OnStop() => StopWorker();

    protected override void OnShutdown() => StopWorker();

    private void StopWorker()
    {
        CancellationTokenSource? cancellation = _stop;
        Task? worker = _serverTask;
        if (cancellation is null) return;
        cancellation.Cancel();
        try
        {
            // Bound SCM stop; never auto-restart or authorize on failure.
            if (worker is not null)
                worker.Wait(TimeSpan.FromSeconds(8));
        }
        catch (AggregateException)
        {
            // Worker errors do not grant any additional capability.
        }
        finally
        {
            _serverTask = null;
            _stop = null;
            cancellation.Dispose();
        }
    }
}
