using DnsPulse.App.ViewModels;
using Wpf.Ui.Controls;

namespace DnsPulse.App;

public sealed partial class MainWindow : FluentWindow
{
    public MainWindow(MainViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        DataContext = viewModel;
        InitializeComponent();
    }
}
