using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Manages Windows Defender Firewall rules for PulseCore listeners via the <c>HNetCfg.FwPolicy2</c> COM API.
/// </summary>
public sealed class FirewallComManager
{
    private const string PolicyProgId = "HNetCfg.FwPolicy2";
    private const string RuleProgId = "HNetCfg.FWRule";
    private const string RuleGrouping = "DNS Pulse";

    private const string RuleDnsUdp = "DnsPulse_PulseCore_DNS_UDP";
    private const string RuleDnsTcp = "DnsPulse_PulseCore_DNS_TCP";
    private const string RuleDohTcp = "DnsPulse_PulseCore_DoH_TCP";
    private const string RuleSidecarPacTcp = "DnsPulse_PulseCore_Sidecar_PAC_TCP";
    private const string RuleSidecarProxyTcp = "DnsPulse_PulseCore_Sidecar_Proxy_TCP";

    private const int ProtocolTcp = 6;
    private const int ProtocolUdp = 17;
    private const int DirectionInbound = 1;
    private const int ActionAllow = 1;
    private const int ProfileAll = 0x7FFFFFFF;

    private static readonly string[] KnownRuleNames =
    [
        RuleDnsUdp,
        RuleDnsTcp,
        RuleDohTcp,
        RuleSidecarPacTcp,
        RuleSidecarProxyTcp
    ];

    /// <summary>
    /// Ensures PulseCore inbound firewall allow rules exist for DNS (UDP/TCP), local DoH, and Sidecar PAC/Proxy ports.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public bool EnsurePulseRules(
        string? applicationPath = null,
        int dnsPort = 53,
        int dohPort = 8443,
        int pacPort = 8080,
        int proxyPort = 8081)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(dnsPort, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(dnsPort, 65535);
        ArgumentOutOfRangeException.ThrowIfLessThan(dohPort, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(dohPort, 65535);
        ArgumentOutOfRangeException.ThrowIfLessThan(pacPort, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(pacPort, 65535);
        ArgumentOutOfRangeException.ThrowIfLessThan(proxyPort, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(proxyPort, 65535);

        INetFwPolicy2? policy = CreatePolicyInstance();
        if (policy is null)
        {
            return false;
        }

        try
        {
            INetFwRules rules = policy.Rules;
            string? resolvedApp = string.IsNullOrWhiteSpace(applicationPath) ? null : applicationPath.Trim();

            UpsertRule(rules, RuleDnsUdp, "Allow DNS Pulse local UDP DNS listener.", ProtocolUdp, dnsPort, resolvedApp);
            UpsertRule(rules, RuleDnsTcp, "Allow DNS Pulse local TCP DNS listener.", ProtocolTcp, dnsPort, resolvedApp);
            UpsertRule(rules, RuleDohTcp, "Allow DNS Pulse local DoH listener.", ProtocolTcp, dohPort, resolvedApp);
            UpsertRule(rules, RuleSidecarPacTcp, "Allow DNS Pulse TLS-split Auto-PAC listener.", ProtocolTcp, pacPort, resolvedApp);
            UpsertRule(rules, RuleSidecarProxyTcp, "Allow DNS Pulse TLS-split proxy listener.", ProtocolTcp, proxyPort, resolvedApp);

            return true;
        }
        catch (COMException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (InvalidCastException)
        {
            return false;
        }
    }

    /// <summary>
    /// Removes all PulseCore-managed Windows Firewall rules.
    /// </summary>
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public bool RemoveAllPulseRules()
    {
        INetFwPolicy2? policy = CreatePolicyInstance();
        if (policy is null)
        {
            return false;
        }

        try
        {
            INetFwRules rules = policy.Rules;
            foreach (string ruleName in KnownRuleNames)
            {
                RemoveRuleBestEffort(rules, ruleName);
            }

            return true;
        }
        catch (COMException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (InvalidCastException)
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the names of PulseCore firewall rules currently present in Windows Firewall.
    /// </summary>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate", Justification = "Queries live Windows Firewall COM policy.")]
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Preserves instance API contract.")]
    public IReadOnlyList<string> GetActivePulseRuleNames()
    {
        INetFwPolicy2? policy = CreatePolicyInstance();
        if (policy is null)
        {
            return [];
        }

        List<string> active = [];

        try
        {
            INetFwRules rules = policy.Rules;
            foreach (string ruleName in KnownRuleNames)
            {
                if (TryGetRule(rules, ruleName) is not null)
                {
                    active.Add(ruleName);
                }
            }
        }
        catch (COMException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        catch (InvalidCastException)
        {
            return [];
        }

        return active;
    }

    private static void UpsertRule(
        INetFwRules rules,
        string ruleName,
        string description,
        int protocol,
        int localPort,
        string? applicationPath)
    {
        RemoveRuleBestEffort(rules, ruleName);

        INetFwRule? rule = CreateRuleInstance();
        if (rule is null)
        {
            return;
        }

        rule.Name = ruleName;
        rule.Description = description;
        rule.Grouping = RuleGrouping;
        rule.Protocol = protocol;
        rule.LocalPorts = localPort.ToString(CultureInfo.InvariantCulture);
        rule.LocalAddresses = "127.0.0.1,::1";
        rule.Direction = DirectionInbound;
        rule.Action = ActionAllow;
        rule.Profiles = ProfileAll;
        rule.EdgeTraversal = false;
        rule.Enabled = true;

        if (!string.IsNullOrWhiteSpace(applicationPath))
        {
            rule.ApplicationName = applicationPath;
        }

        rules.Add(rule);
    }

    private static INetFwRule? TryGetRule(INetFwRules rules, string ruleName)
    {
        try
        {
            return rules.Item(ruleName);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (COMException)
        {
            return null;
        }
    }

    private static void RemoveRuleBestEffort(INetFwRules rules, string ruleName)
    {
        try
        {
            rules.Remove(ruleName);
        }
        catch (FileNotFoundException)
        {
        }
        catch (COMException)
        {
        }
    }

    private static INetFwPolicy2? CreatePolicyInstance()
    {
        Type? policyType = Type.GetTypeFromProgID(PolicyProgId, throwOnError: false);
        if (policyType is null)
        {
            return null;
        }

        try
        {
            return Activator.CreateInstance(policyType) as INetFwPolicy2;
        }
        catch (COMException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static INetFwRule? CreateRuleInstance()
    {
        Type? ruleType = Type.GetTypeFromProgID(RuleProgId, throwOnError: false);
        if (ruleType is null)
        {
            return null;
        }

        try
        {
            return Activator.CreateInstance(ruleType) as INetFwRule;
        }
        catch (COMException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    [ComImport]
    [Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    private interface INetFwPolicy2
    {
        [DispId(1)]
        int CurrentProfileTypes { get; }

        [DispId(7)]
        INetFwRules Rules { get; }
    }

    [ComImport]
    [Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    private interface INetFwRules
    {
        [DispId(1)]
        int Count { get; }

        [DispId(2)]
        void Add(INetFwRule rule);

        [DispId(3)]
        void Remove(string name);

        [DispId(4)]
        INetFwRule Item(string name);
    }

    [ComImport]
    [Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    private interface INetFwRule
    {
        [DispId(1)]
        string Name { get; set; }

        [DispId(2)]
        string Description { get; set; }

        [DispId(3)]
        string ApplicationName { get; set; }

        [DispId(4)]
        string ServiceName { get; set; }

        [DispId(5)]
        int Protocol { get; set; }

        [DispId(6)]
        string LocalPorts { get; set; }

        [DispId(7)]
        string RemotePorts { get; set; }

        [DispId(8)]
        string LocalAddresses { get; set; }

        [DispId(9)]
        string RemoteAddresses { get; set; }

        [DispId(10)]
        string IcmpTypesAndCodes { get; set; }

        [DispId(11)]
        int Direction { get; set; }

        [DispId(12)]
        object Interfaces { get; set; }

        [DispId(13)]
        string InterfaceTypes { get; set; }

        [DispId(14)]
        bool Enabled { get; set; }

        [DispId(15)]
        string Grouping { get; set; }

        [DispId(16)]
        int Profiles { get; set; }

        [DispId(17)]
        bool EdgeTraversal { get; set; }

        [DispId(18)]
        int Action { get; set; }
    }
}
