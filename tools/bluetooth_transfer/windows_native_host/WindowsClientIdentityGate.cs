// PALACO v5.2: Windows service-SID and pipe-client identity guard.
// Diagnostic-only. A verified Windows token is NOT a release capability.
// Real service provisioning, DACL audit and hardware validation remain HOLD.
using System.IO.Pipes;
using System.Security;
using System.Security.Principal;

namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsClientIdentityGate
{
    private const string ServiceAccount = @"NT SERVICE\PALACO-BT-Diagnostic-HOLD";

    // Service SIDs appear in the process token's groups, not necessarily User.
    // This check is intended for SCM service mode ONLY, and fails closed if the
    // service isn't provisioned with a service-specific SID.
    internal static bool HasExpectedServiceSid()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            var expected = (SecurityIdentifier)new NTAccount(ServiceAccount)
                .Translate(typeof(SecurityIdentifier));
            using WindowsIdentity process = WindowsIdentity.GetCurrent();
            return process.Groups is not null
                && process.Groups.Cast<IdentityReference>().Any(
                    group => group is SecurityIdentifier sid && sid.Equals(expected));
        }
        catch (Exception ex) when (ex is IdentityNotMappedException
                                    or SecurityException or UnauthorizedAccessException
                                    or SystemException)
        {
            return false;
        }
    }

    // RunAsClient requests OS-level pipe-client impersonation. It is separate
    // from JSON claims and the process-account DACL. If the peer cannot be
    // impersonated, we refuse even the diagnostic response.
    internal static bool IsExpectedSameAccountClient(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows() || pipe is null || !pipe.IsConnected)
            return false;
        try
        {
            using WindowsIdentity process = WindowsIdentity.GetCurrent();
            string? expected = process.User?.Value;
            if (string.IsNullOrEmpty(expected)) return false;
            bool matches = false;
            pipe.RunAsClient(() =>
            {
                using WindowsIdentity client = WindowsIdentity.GetCurrent(true);
                string? actual = client?.User?.Value;
                matches = MatchesExpectedAccount(expected, actual);
            });
            return matches;
        }
        catch (Exception ex) when (ex is IOException or SecurityException
                                    or UnauthorizedAccessException
                                    or InvalidOperationException or SystemException)
        {
            return false;
        }
    }

    internal static bool MatchesExpectedAccount(string? expected, string? actual)
    {
        // Pure policy check for offline negative-path self-tests.
        return !string.IsNullOrWhiteSpace(expected)
            && !string.IsNullOrWhiteSpace(actual)
            && expected.StartsWith("S-1-", StringComparison.Ordinal)
            && string.Equals(expected, actual, StringComparison.Ordinal);
    }
}
