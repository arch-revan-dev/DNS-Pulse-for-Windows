using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DnsPulse.Platform.Windows.Ipc;

/// <summary>
/// Builds hardened Windows Named Pipe DACLs restricted to LocalSystem, Builtin Administrators,
/// and the interactive user, explicitly excluding public and anonymous SIDs.
/// </summary>
public static class PipeSecurityBuilder
{
    /// <summary>
    /// Canonical control pipe name shared between <c>DnsPulse.Service</c> and desktop UI clients.
    /// </summary>
    public const string DefaultPipeName = "DnsPulse.Control.v1";

    /// <summary>
    /// Creates a restricted <see cref="PipeSecurity"/> granting <see cref="PipeAccessRights.FullControl"/>
    /// solely to LocalSystem, Builtin Administrators, and <paramref name="interactiveUserSid"/>
    /// (defaulting to the current Windows user, or Authenticated Users only if the user SID is unavailable).
    /// </summary>
    public static PipeSecurity CreateRestrictedPipeSecurity(SecurityIdentifier? interactiveUserSid = null)
    {
        if (interactiveUserSid is not null && IsPublicOrAnonymousSid(interactiveUserSid))
        {
            throw new ArgumentException(
                "Public, guest, or anonymous security identifiers cannot be granted named pipe access.",
                nameof(interactiveUserSid));
        }

        PipeSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        SecurityIdentifier systemSid = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier adminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier userSid = interactiveUserSid ?? ResolveCurrentOrAuthenticatedUserSid();

        security.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(adminsSid, PipeAccessRights.FullControl, AccessControlType.Allow));

        if (!userSid.Equals(systemSid) && !userSid.Equals(adminsSid))
        {
            security.AddAccessRule(new PipeAccessRule(userSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        if (IsPublicOrAnonymousAccessPresent(security))
        {
            throw new InvalidOperationException("Public or anonymous access rule detected on hardened PipeSecurity.");
        }

        return security;
    }

    /// <summary>
    /// Audits a <see cref="PipeSecurity"/> DACL and returns <see langword="true"/> if any allow rule grants
    /// access to Everyone (<see cref="WellKnownSidType.WorldSid"/>), Anonymous (<see cref="WellKnownSidType.AnonymousSid"/>),
    /// or Guests (<see cref="WellKnownSidType.BuiltinGuestsSid"/>).
    /// </summary>
    public static bool IsPublicOrAnonymousAccessPresent(PipeSecurity security)
    {
        ArgumentNullException.ThrowIfNull(security);

        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));

        foreach (AuthorizationRule rule in rules)
        {
            if (rule is PipeAccessRule pipeRule
                && pipeRule.AccessControlType == AccessControlType.Allow
                && pipeRule.IdentityReference is SecurityIdentifier sid
                && IsPublicOrAnonymousSid(sid))
            {
                return true;
            }
        }

        return false;
    }

    private static SecurityIdentifier ResolveCurrentOrAuthenticatedUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User ?? new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
    }

    private static bool IsPublicOrAnonymousSid(SecurityIdentifier sid)
    {
        return sid.IsWellKnown(WellKnownSidType.WorldSid)
            || sid.IsWellKnown(WellKnownSidType.AnonymousSid)
            || sid.IsWellKnown(WellKnownSidType.BuiltinGuestsSid);
    }
}
