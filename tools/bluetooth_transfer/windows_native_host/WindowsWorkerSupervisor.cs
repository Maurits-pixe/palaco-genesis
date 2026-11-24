// PALACO Bluetooth v5.9 - fail-closed worker supervision.
// No automatic service restart, no authorization and no incident payload data.
// The callback must request SCM stop (or terminate the service on failure).
namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsWorkerSupervisor
{
    internal const string UnexpectedExit = "WORKER_EXIT_UNEXPECTED";
    internal const string WorkerFault = "WORKER_FAULTED";

    internal static void Observe(
        Task worker, CancellationToken intentionalStop, Action<string> onIncident)
    {
        ArgumentNullException.ThrowIfNull(worker);
        ArgumentNullException.ThrowIfNull(onIncident);

        _ = worker.ContinueWith(completed =>
        {
            if (completed.IsFaulted)
                _ = completed.Exception; // Observe exception without exposing sensitive details.

            if (intentionalStop.IsCancellationRequested)
                return;

            string code = completed.IsFaulted ? WorkerFault : UnexpectedExit;
            // No retry or worker restart on any unexpected termination.
            onIncident(code);
        }, CancellationToken.None,
           TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    internal static bool SelfTest()
    {
        int incidents = 0;
        string? last = null;
        void Record(string code)
        {
            incidents++;
            last = code;
        }

        // A healthy but unexpectedly completed worker is still a failure.
        Observe(Task.CompletedTask, CancellationToken.None, Record);
        bool earlyExit = incidents == 1 && last == UnexpectedExit;

        // Faulted worker also triggers exactly one incident with a fixed code.
        Observe(Task.FromException(new InvalidOperationException("synthetic worker failure")),
                CancellationToken.None, Record);
        bool fault = incidents == 2 && last == WorkerFault;

        // Intentional shutdown is not an incident and must never auto-restart.
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Observe(Task.CompletedTask, stop.Token, Record);
        bool cancelled = incidents == 2;

        Console.WriteLine(earlyExit && fault && cancelled
            ? "Windows worker supervisor self-test PASS (fail closed, no restart)"
            : "Windows worker supervisor self-test FAIL");
        return earlyExit && fault && cancelled;
    }
}
