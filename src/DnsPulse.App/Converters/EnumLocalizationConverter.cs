using System.Globalization;
using System.Windows.Data;
using DnsPulse.App.ViewModels;
using DnsPulse.Core.Models;
using DnsPulse.Core.Routing;
using DnsPulse.Core.Wire;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Updates;

namespace DnsPulse.App.Converters;

/// <summary>
/// Converts technical domain enums and option identifiers (<see cref="RouteZone"/>, <see cref="DnsResponseCode"/>,
/// <see cref="DiagnosticVerdict"/>, <see cref="InterceptionMode"/>, <see cref="PoolSelectionStrategy"/>,
/// <see cref="UpdateChannel"/>, <see cref="ServerSortOrder"/>, <see cref="RuleFormatKind"/>, and accent preset keys)
/// into localized plain-language labels via <see cref="LocalizationSource"/>.
/// </summary>
public sealed class EnumLocalizationConverter : IValueConverter, IMultiValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is null)
        {
            return string.Empty;
        }

        string? key = value switch
        {
            ServerDisplayCategory category => category switch
            {
                ServerDisplayCategory.AiAndGeoUnlock => "Servers_Category_AiGeo",
                ServerDisplayCategory.FastEncrypted => "Servers_Category_FastEncrypted",
                ServerDisplayCategory.StreamingAndGaming => "Servers_Category_StreamingGaming",
                ServerDisplayCategory.CustomAndDiscovered => "Servers_Category_Custom",
                _ => null
            },
            RouteZone zone => zone switch
            {
                RouteZone.Zone1LocalBypass => "Zone_Zone1LocalBypass",
                RouteZone.Zone2BlockOrProtect => "Zone_Zone2BlockOrProtect",
                RouteZone.Zone3GeoUnlock => "Zone_Zone3GeoUnlock",
                RouteZone.Zone4EncryptedTrusted => "Zone_Zone4EncryptedTrusted",
                _ => "Zone_None"
            },
            DnsResponseCode rcode => rcode switch
            {
                DnsResponseCode.NoError => "RCode_NoError",
                DnsResponseCode.NxDomain => "RCode_NxDomain",
                DnsResponseCode.ServFail => "RCode_ServFail",
                DnsResponseCode.Refused => "RCode_Refused",
                DnsResponseCode.FormErr => "RCode_FormErr",
                DnsResponseCode.NotImp => "RCode_NotImp",
                _ => "RCode_Other"
            },
            DiagnosticVerdict verdict => verdict switch
            {
                DiagnosticVerdict.Healthy => "Diag_Verdict_Healthy",
                DiagnosticVerdict.LocalPort53Conflict => "Diag_Verdict_LocalPort53Conflict",
                DiagnosticVerdict.DnsPoisoned => "Diag_Verdict_DnsPoisoned",
                DiagnosticVerdict.EncryptedDnsDpiBlocked => "Diag_Verdict_EncryptedDnsDpiBlocked",
                DiagnosticVerdict.TlsSniDpiReset => "Diag_Verdict_TlsSniDpiReset",
                DiagnosticVerdict.IpBlockedByIsp => "Diag_Verdict_IpBlockedByIsp",
                DiagnosticVerdict.GeoBlockedByService => "Diag_Verdict_GeoBlockedByService",
                DiagnosticVerdict.TlsMitmRejected => "Diag_Verdict_TlsMitmRejected",
                DiagnosticVerdict.BrowserDohBypass => "Diag_Verdict_BrowserDohBypass",
                _ => "Diag_Verdict_Unknown"
            },
            InterceptionMode mode => mode switch
            {
                InterceptionMode.AdapterDns => "Settings_Mode_AdapterDns",
                InterceptionMode.SplitNrpt => "Settings_Mode_SplitNrpt",
                InterceptionMode.LocalProxyPacOnly => "Settings_Mode_LocalProxyPacOnly",
                InterceptionMode.WfpDivertPlugin => "Settings_Mode_WfpDivertPlugin",
                _ => "Overview_State_Disconnected"
            },
            PoolSelectionStrategy strategy => strategy switch
            {
                PoolSelectionStrategy.Fastest => "Settings_PoolStrategy_Fastest",
                PoolSelectionStrategy.Parallel => "Settings_PoolStrategy_Parallel",
                PoolSelectionStrategy.Failover => "Settings_PoolStrategy_Failover",
                PoolSelectionStrategy.LoadBalance => "Settings_PoolStrategy_LoadBalance",
                _ => "Settings_PoolStrategy_Fastest"
            },
            UpdateChannel channel => channel switch
            {
                UpdateChannel.Beta => "Settings_Channel_Beta",
                _ => "Settings_Channel_Stable"
            },
            ServerSortOrder sortOrder => sortOrder switch
            {
                ServerSortOrder.P50Latency => "Servers_Sort_P50",
                ServerSortOrder.Protocol => "Servers_Sort_Protocol",
                ServerSortOrder.TrustTier => "Servers_Sort_Trust",
                ServerSortOrder.Name => "Servers_Sort_Name",
                _ => "Servers_Sort_P50"
            },
            RuleFormatKind ruleFormat => ruleFormat switch
            {
                RuleFormatKind.Json => "Routing_Format_Json",
                RuleFormatKind.AdGuard => "Routing_Format_AdGuard",
                RuleFormatKind.Hosts => "Routing_Format_Hosts",
                _ => "Routing_Format_Json"
            },
            TrustTier tier => tier switch
            {
                TrustTier.Tier1EncryptedTrusted => "Servers_Badge_Trust_Fast",
                TrustTier.Tier2VerifiedGeoUnlock => "Servers_Badge_Trust_Geo",
                TrustTier.Tier3CustomOrSelfHosted => "Servers_Badge_Trust_Custom",
                TrustTier.Tier4ExperimentalLab => "Servers_Badge_Trust_Lab",
                _ => "Servers_Badge_Trust_Custom"
            },
            string text => text switch
            {
                "Emerald" => "Accent_Emerald",
                "Azure" => "Accent_Azure",
                "Violet" => "Accent_Violet",
                "Amber" => "Accent_Amber",
                "Rose" => "Accent_Rose",
                "Auto" => "Settings_Bootstrap_Auto",
                _ => null
            },
            _ => null
        };

        return key is not null
            ? LocalizationSource.Instance[key]
            : value.ToString() ?? string.Empty;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return System.Windows.Data.Binding.DoNothing;
    }

    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(values);
        object? primary = values.Length > 0 ? values[0] : null;
        return Convert(primary, targetType, parameter, culture);
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture)
    {
        return [];
    }
}
