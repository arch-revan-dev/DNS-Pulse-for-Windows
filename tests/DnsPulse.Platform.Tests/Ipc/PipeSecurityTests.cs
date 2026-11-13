using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using DnsPulse.Platform.Windows.Ipc;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Ipc;

public sealed class PipeSecurityTests
{
    [Fact]
    public void CreateRestrictedPipeSecurity_AllowsLocalSystemAdminsAndCurrentUser_AndDeniesPublicAndAnonymous()
    {
        using WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
        SecurityIdentifier currentUserSid = currentIdentity.User
            ?? new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);

        PipeSecurity security = PipeSecurityBuilder.CreateRestrictedPipeSecurity();

        PipeSecurityBuilder.IsPublicOrAnonymousAccessPresent(security).Should().BeFalse();

        List<PipeAccessRule> allowRules = GetAllowRules(security);
        allowRules.Should().NotBeEmpty();

        SecurityIdentifier systemSid = new(WellKnownSidType.LocalSystemSid, null);
        SecurityIdentifier adminsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        SecurityIdentifier everyoneSid = new(WellKnownSidType.WorldSid, null);
        SecurityIdentifier anonymousSid = new(WellKnownSidType.AnonymousSid, null);
        SecurityIdentifier guestsSid = new(WellKnownSidType.BuiltinGuestsSid, null);
        SecurityIdentifier untrustedSid = new(WellKnownSidType.BuiltinUsersSid, null);

        allowRules.Should().Contain(r =>
            r.IdentityReference.Equals(systemSid)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));

        allowRules.Should().Contain(r =>
            r.IdentityReference.Equals(adminsSid)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));

        allowRules.Should().Contain(r =>
            r.IdentityReference.Equals(currentUserSid)
            && r.PipeAccessRights.HasFlag(PipeAccessRights.FullControl));

        allowRules.Should().NotContain(r => r.IdentityReference.Equals(everyoneSid));
        allowRules.Should().NotContain(r => r.IdentityReference.Equals(anonymousSid));
        allowRules.Should().NotContain(r => r.IdentityReference.Equals(guestsSid));
        if (!currentUserSid.Equals(untrustedSid))
        {
            allowRules.Should().NotContain(r => r.IdentityReference.Equals(untrustedSid));
        }
    }

    [Fact]
    public void CreateRestrictedPipeSecurity_RejectsExplicitPublicOrAnonymousSid()
    {
        SecurityIdentifier everyoneSid = new(WellKnownSidType.WorldSid, null);
        SecurityIdentifier anonymousSid = new(WellKnownSidType.AnonymousSid, null);

        Action actEveryone = () => PipeSecurityBuilder.CreateRestrictedPipeSecurity(everyoneSid);
        Action actAnonymous = () => PipeSecurityBuilder.CreateRestrictedPipeSecurity(anonymousSid);

        actEveryone.Should().Throw<ArgumentException>();
        actAnonymous.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void IsPublicOrAnonymousAccessPresent_DetectsWorldOrAnonymousAllowRules()
    {
        PipeSecurity worldSecurity = new();
        worldSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        PipeSecurity anonymousSecurity = new();
        anonymousSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AnonymousSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        PipeSecurityBuilder.IsPublicOrAnonymousAccessPresent(worldSecurity).Should().BeTrue();
        PipeSecurityBuilder.IsPublicOrAnonymousAccessPresent(anonymousSecurity).Should().BeTrue();
    }

    private static List<PipeAccessRule> GetAllowRules(PipeSecurity security)
    {
        AuthorizationRuleCollection rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            typeof(SecurityIdentifier));

        List<PipeAccessRule> allowRules = [];
        foreach (AuthorizationRule rule in rules)
        {
            if (rule is PipeAccessRule pipeRule && pipeRule.AccessControlType == AccessControlType.Allow)
            {
                allowRules.Add(pipeRule);
            }
        }

        return allowRules;
    }
}
