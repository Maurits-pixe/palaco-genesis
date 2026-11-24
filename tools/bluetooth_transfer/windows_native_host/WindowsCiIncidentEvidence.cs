// CI-only incident evidence for an intentionally faulted diagnostic SCM worker.
// Unkeyed SHA-256 detects accidental alteration; NOT an authenticating signature.
// Never enabled for production service mode or usable as an authorization grant.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsCiIncidentEvidence
{
    internal const string MarkerName = "palaco-ci-fault.marker";
    internal const string EvidenceName = "palaco-ci-incident.json";

    internal static bool MarkerPresent()
    {
        if (!OperatingSystem.IsWindows()) return false;
        return File.Exists(Path.Combine(AppContext.BaseDirectory, MarkerName));
    }

    internal static void Record(string code)
    {
        if (!MarkerPresent() || code != WindowsWorkerSupervisor.WorkerFault)
            throw new UnauthorizedAccessException("CI fault evidence gate closed");

        // Deterministic canonical fields only; no client identity or secrets.
        string canonical = "PALACO-BT-CI-INCIDENT-V1|WORKER_FAULTED|HOLD|DENY";
        string hash = Convert.ToHexString(
            SHA256.HashData(Encoding.ASCII.GetBytes(canonical))).ToLowerInvariant();
        var evidence = new
        {
            protocol = "PALACO-BT-CI-INCIDENT-V1",
            incident = code,
            decision = "HOLD",
            authorization = "DENY",
            canonical_sha256 = hash,
            independent_signature = false,
            native_security_verified = false
        };
        string path = Path.Combine(AppContext.BaseDirectory, EvidenceName);
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                                        FileShare.None);
        JsonSerializer.Serialize(file, evidence);
        file.Flush(flushToDisk: true);
    }
}
