// Windows-only IPC ACL construction for DRAFT/HOLD diagnostic server.
// This is an account SID DACL, NOT a verified service SID / authorized caller.
// Do not use this same-account boundary as an authorization policy.
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsPipeSecurity
{
    internal static NamedPipeServerStream CreateDiagnosticPipe()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows IPC only");

        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        SecurityIdentifier sid = identity.User
            ?? throw new UnauthorizedAccessException("Windows process SID unavailable");
        if (sid.IsWellKnown(WellKnownSidType.AnonymousSid)
            || sid.IsWellKnown(WellKnownSidType.WorldSid))
            throw new UnauthorizedAccessException("Untrusted process SID");

        var acl = new PipeSecurity();
        // Disable inherited broad permissions and allow only this process account.
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.AddAccessRule(new PipeAccessRule(
            sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));

        // Explicit protected account-SID DACL replaces CurrentUserOnly:
        // .NET forbids supplying PipeSecurity together with that option.
        // A LocalSystem caller can still share the account SID.
        return NamedPipeServerStreamAcl.Create(
            "PALACO-BT-NATIVE-DIAGNOSTIC-V1",
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            0, 0, acl);
    }
}
