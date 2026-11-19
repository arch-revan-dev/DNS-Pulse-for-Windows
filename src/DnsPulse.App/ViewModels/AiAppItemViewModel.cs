using CommunityToolkit.Mvvm.ComponentModel;
using DnsPulse.Core.Models;

namespace DnsPulse.App.ViewModels;

/// <summary>
/// Presentation wrapper for a detected desktop or CLI AI application (Antigravity, Claude Code, Cursor, Windsurf, etc.).
/// </summary>
public sealed partial class AiAppItemViewModel : ObservableObject
{
    [ObservableProperty]
    private bool _isInstalled;

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private string? _executablePath;

    [ObservableProperty]
    private string _statusBadgeText = string.Empty;

    public AiAppItemViewModel(
        AiAppProfile profile,
        bool isInstalled,
        bool isRunning,
        string? executablePath,
        string statusBadgeText)
    {
        ArgumentNullException.ThrowIfNull(profile);

        Profile = profile;
        _isInstalled = isInstalled;
        _isRunning = isRunning;
        _executablePath = executablePath;
        _statusBadgeText = statusBadgeText;
    }

    public AiAppProfile Profile { get; }

    public string Id => Profile.Id;

    public string DisplayName => Profile.DisplayName;

    public string Category => Profile.Category;

    public string PrimaryDomain => Profile.Domains.Count > 0 ? Profile.Domains[0] : string.Empty;

    public string Notes => Profile.Notes;
}
