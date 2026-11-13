namespace DnsPulse.Core.Models;

/// <summary>
/// Target domain preset used for probing and scoped Geo-Unlock configuration.
/// </summary>
public sealed record DomainPresetItem(
    string Id,
    string GroupId,
    string Label,
    string Domain,
    bool RequiresBypass,
    bool IsSelected = false);
