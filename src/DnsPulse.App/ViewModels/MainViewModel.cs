using CommunityToolkit.Mvvm.ComponentModel;
using DnsPulse.Platform.Windows;

namespace DnsPulse.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private string _title = $"{WindowsPlatformInfo.Product} — PulseCore";
}
