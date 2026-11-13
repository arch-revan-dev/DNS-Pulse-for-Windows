using DnsPulse.Engine;

namespace DnsPulse.Platform.Windows;

/// <summary>
/// Assembly marker for Windows-specific DNS Pulse platform adapters.
/// </summary>
public static class WindowsPlatformInfo
{
    public static string Product => EngineAssemblyInfo.Product;
}
