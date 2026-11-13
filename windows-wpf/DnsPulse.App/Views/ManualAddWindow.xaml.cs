using System.Windows;
using System.Windows.Controls;
using DnsPulse.App.Models;
using DnsPulse.App.ViewModels;

namespace DnsPulse.App.Views;

public partial class ManualAddWindow : Window
{
    private readonly MainViewModel _vm;

    public ManualAddWindow(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
    }

    private void OnCancelClick(object sender, RoutedEventArgs e) => Close();

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        var endpoint = EndpointInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            ErrorText.Text = "Укажите DoH URL, DoT домен или IP-адрес сервера.";
            ErrorText.Visibility = Visibility.Visible;
            return;
        }

        var protoTag = (ProtocolCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "DoH";
        var protocol = Enum.TryParse<DnsProtocol>(protoTag, out var parsedProto) ? parsedProto : DnsProtocol.DoH;
        var name = string.IsNullOrWhiteSpace(NameInput.Text) ? endpoint : NameInput.Text.Trim();
        var provider = string.IsNullOrWhiteSpace(ProviderInput.Text) ? "Пользовательский" : ProviderInput.Text.Trim();

        var entry = new DnsServerEntry
        {
            Id = $"custom_{Guid.NewGuid():N}"[..16],
            Name = name,
            Provider = provider,
            Protocol = protocol,
            DohUrl = protocol == DnsProtocol.DoH ? endpoint : null,
            DotHost = protocol == DnsProtocol.DoT ? endpoint.Replace("tls://", "", StringComparison.OrdinalIgnoreCase).Split(':')[0] : null,
            SmartProxyIp = protocol == DnsProtocol.SNI443 ? endpoint.Replace("smartproxy://", "", StringComparison.OrdinalIgnoreCase).Split(':')[0] : null,
            PrimaryIp = protocol == DnsProtocol.UDP ? endpoint : "",
            Category = "Свои / Найденные",
            Country = "CUSTOM",
            SupportsBypass = BypassCheck.IsChecked == true,
            IsBuiltin = false,
            IsFreeUnlimited = true,
            Description = "Пользовательский DNS-сервер (сохранён в SQLite + JSON-сейф)"
        };

        _vm.AddCustomServer(entry);
        Close();
    }
}
