using DnsPulse.Core;

namespace DnsPulse.Engine;

/// <summary>
/// Assembly marker for the cross-platform DNS Pulse engine layer.
/// </summary>
public static class EngineAssemblyInfo
{
    public static string Product => CoreAssemblyInfo.ProductName;
}
