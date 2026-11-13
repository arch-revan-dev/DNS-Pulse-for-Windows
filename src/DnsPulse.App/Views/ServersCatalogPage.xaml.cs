using System.Windows;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

/// <summary>
/// Servers &amp; Catalog page featuring 4 Trust Tier tabs/chips, benchmark runner, import/sync, and Self-Hosted VPS Wizard.
/// </summary>
public sealed partial class ServersCatalogPage : System.Windows.Controls.UserControl
{
    public ServersCatalogPage(ServersCatalogViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        DataContext = viewModel;
        InitializeComponent();
    }

    private void OnCopyTextClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string text } && !string.IsNullOrEmpty(text))
        {
            System.Windows.Clipboard.SetText(text);
        }
    }
}
