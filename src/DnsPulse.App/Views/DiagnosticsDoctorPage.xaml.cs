using System.Windows;
using DnsPulse.App.ViewModels;
using DnsPulse.Core.Models;

namespace DnsPulse.App.Views;

/// <summary>
/// Diagnostics Doctor page hosting the 6-Layer Troubleshooter, Advanced Network Lab, and LAN Gateway QR panel.
/// </summary>
public sealed partial class DiagnosticsDoctorPage : System.Windows.Controls.UserControl
{
    private readonly DiagnosticsDoctorViewModel _viewModel;

    public DiagnosticsDoctorPage(DiagnosticsDoctorViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        _viewModel = viewModel;
        DataContext = viewModel;
        InitializeComponent();
    }

    private void OnPresetChipClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: DomainPresetItem preset })
        {
            _viewModel.SelectedPreset = preset;
        }
    }

    private void OnCopyEndpointClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string value } && !string.IsNullOrEmpty(value))
        {
            System.Windows.Clipboard.SetText(value);
        }
    }
}
