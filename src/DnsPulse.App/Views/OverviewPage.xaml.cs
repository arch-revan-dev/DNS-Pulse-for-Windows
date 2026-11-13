using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

/// <summary>
/// Overview dashboard page displaying hero connection status, strategy profiles, and live telemetry strip.
/// </summary>
public sealed partial class OverviewPage : System.Windows.Controls.UserControl
{
    public OverviewPage(OverviewViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        DataContext = viewModel;
        InitializeComponent();
    }
}
