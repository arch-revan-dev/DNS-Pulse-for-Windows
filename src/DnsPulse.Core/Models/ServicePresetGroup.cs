namespace DnsPulse.Core.Models;

/// <summary>
/// Logical preset category group (e.g., AI, Streaming, Gaming, All, Custom).
/// </summary>
public sealed record ServicePresetGroup(string Id, string Label, bool IsSelected = false);
