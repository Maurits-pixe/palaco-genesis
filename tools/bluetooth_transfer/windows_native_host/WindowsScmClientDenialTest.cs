// PALACO Bluetooth v5.8 - external-client denial against the ACTUAL SCM host.
// The existing Windows CI runner token is not LocalSystem. Deny-only.
// A timeout is NOT proof of ACL denial: only Windows ACCESS_DENIED qualifies.
using System.IO.Pipes;
using System.Security.Principal;

namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsScmClientDenialTest
{
    internal static async Task<bool> RunAsync()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (identity.User is null ||
            identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid))
        {
            Console.Error.WriteLine("SCM rejection probe requires non-System caller");
            return false;
        }
        using var client = new NamedPipeClientStream(
            ".", "PALACO-BT-NATIVE-DIAGNOSTIC-V1",
            PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        try
        {
            await client.ConnectAsync(3000, deadline.Token);
            Console.Error.WriteLine("SCM client isolation FAIL: non-System user connected");
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("SCM client isolation PASS: Windows ACCESS_DENIED");
            return true;
        }
        catch (IOException ex) when ((uint)ex.HResult == 0x80070005u)
        {
            Console.WriteLine("SCM client isolation PASS: Windows ACCESS_DENIED");
            return true;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException
                                      or OperationCanceledException)
        {
            Console.Error.WriteLine(
                "SCM client isolation INCONCLUSIVE (not ACCESS_DENIED): "
                + ex.GetType().Name);
            return false;
        }
    }
}
