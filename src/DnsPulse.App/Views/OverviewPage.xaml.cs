using System.Windows;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

/// <summary>
/// Overview dashboard page displaying the 1-2-3 guided quick-connect hero, strategy profiles, and live telemetry strip.
/// </summary>
public sealed partial class OverviewPage : System.Windows.Controls.UserControl
{
    private readonly OverviewViewModel _viewModel;

    public OverviewPage(OverviewViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        _viewModel = viewModel;
        DataContext = viewModel;
        InitializeComponent();
    }

    private void OnQuickServiceChipClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: QuickServiceOption option })
        {
            _viewModel.SelectedQuickService = option;
        }
    }
}
