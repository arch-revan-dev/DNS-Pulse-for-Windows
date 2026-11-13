namespace DnsPulse.Core.Routing;

/// <summary>
/// Represents the deterministic routing outcome for a queried domain name.
/// </summary>
/// <param name="Zone">The resolved routing zone.</param>
/// <param name="IsBlocked">Whether the query should be sinkholed/blocked.</param>
/// <param name="IsSecurityPinned">Whether the domain is pinned to trusted encrypted DNS and forbidden from Zone 3 routing.</param>
/// <param name="MatchedRule">The matched pattern or rule string (or <c>"*"</c> for default internet fallback).</param>
/// <param name="TargetProfileId">Optional upstream profile identifier associated with the matched rule.</param>
public sealed record RouteDecision(
    RouteZone Zone,
    bool IsBlocked,
    bool IsSecurityPinned,
    string MatchedRule,
    string? TargetProfileId);
