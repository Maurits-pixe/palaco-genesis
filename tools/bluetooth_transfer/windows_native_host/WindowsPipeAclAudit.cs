// Read-only DACL inspection for the diagnostic named-pipe security object.
// This audits the intended account-only rule, not cross-account OS enforcement.
// No privilege elevation, service provisioning, import, or TPM operations.
using System.Security.AccessControl;
using System.Security.Principal;

namespace Palaco.Bluetooth.NativeHost;

internal static class WindowsPipeAclAudit
{
    internal static bool IsSingleAccountRule(PipeSecurity? acl, SecurityIdentifier? account)
    {
        if (!OperatingSystem.IsWindows() || acl is null || account is null)
            return false;

        try
        {
            if (!acl.AreAccessRulesProtected)
                return false;
            AuthorizationRuleCollection rules = acl.GetAccessRules(
                includeExplicit: true, includeInherited: true,
                targetType: typeof(SecurityIdentifier));
            if (rules.Count != 1 || rules[0] is not PipeAccessRule rule)
                return false;
            if (rule.AccessControlType != AccessControlType.Allow || rule.IsInherited)
                return false;
            if (rule.IdentityReference is not SecurityIdentifier sid || !sid.Equals(account))
                return false;
            // Read/write only. Never accept FullControl, TakeOwnership or
            // ChangePermissions, which could alter the pipe's access policy.
            PipeAccessRights access = rule.PipeAccessRights;
            if ((access & PipeAccessRights.ReadWrite) != PipeAccessRights.ReadWrite)
                return false;
            return (access & (PipeAccessRights.ChangePermissions
                              | PipeAccessRights.TakeOwnership
                              | PipeAccessRights.CreateNewInstance)) == 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                    or UnauthorizedAccessException
                                    or ArgumentException)
        {
            return false;
        }
    }

    internal static bool RunOfflineSelfTests()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        SecurityIdentifier? account = current.User;
        if (account is null) return false;

        var good = new PipeSecurity();
        good.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        good.AddAccessRule(new PipeAccessRule(account, PipeAccessRights.ReadWrite,
                                             AccessControlType.Allow));

        var world = new PipeSecurity();
        world.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        world.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        var inherited = new PipeSecurity();
        inherited.AddAccessRule(new PipeAccessRule(account, PipeAccessRights.ReadWrite,
                                                   AccessControlType.Allow));

        var broad = new PipeSecurity();
        broad.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        broad.AddAccessRule(new PipeAccessRule(account, PipeAccessRights.FullControl,
                                              AccessControlType.Allow));

        var multiple = new PipeSecurity();
        multiple.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        multiple.AddAccessRule(new PipeAccessRule(account, PipeAccessRights.ReadWrite,
                                                 AccessControlType.Allow));
        multiple.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.ReadWrite, AccessControlType.Allow));

        return IsSingleAccountRule(good, account)
            && !IsSingleAccountRule(world, account)
            && !IsSingleAccountRule(inherited, account)
            && !IsSingleAccountRule(broad, account)
            && !IsSingleAccountRule(multiple, account)
            && !IsSingleAccountRule(null, account);
    }
}
