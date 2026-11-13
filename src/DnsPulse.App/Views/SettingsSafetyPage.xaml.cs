using System.Windows;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

/// <summary>
/// Settings &amp; Safety page managing autostart, interception modes, privacy guards, theme/language, updates, and emergency recovery.
/// </summary>
public sealed partial class SettingsSafetyPage : System.Windows.Controls.UserControl
{
    private readonly SettingsSafetyViewModel _viewModel;
    private bool _isSyncingPassword;

    public SettingsSafetyPage(SettingsSafetyViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        _viewModel = viewModel;
        DataContext = viewModel;
        InitializeComponent();

        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        _isSyncingPassword = true;
        try
        {
            if (!string.Equals(GitHubTokenBox.Password, _viewModel.GitHubToken, StringComparison.Ordinal))
            {
                GitHubTokenBox.Password = _viewModel.GitHubToken;
            }
        }
        finally
        {
            _isSyncingPassword = false;
        }
    }

    private void OnGitHubTokenChanged(object sender, RoutedEventArgs e)
    {
        if (_isSyncingPassword)
        {
            return;
        }

        _viewModel.GitHubToken = GitHubTokenBox.Password;
    }
}
