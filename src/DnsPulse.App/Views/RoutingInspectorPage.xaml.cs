using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

/// <summary>
/// Routing &amp; Inspector page with service Geo-Unlock presets, rule import/export, and virtualized query telemetry.
/// </summary>
public sealed partial class RoutingInspectorPage : System.Windows.Controls.UserControl
{
    public RoutingInspectorPage(RoutingInspectorViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        DataContext = viewModel;
        InitializeComponent();
    }
}
