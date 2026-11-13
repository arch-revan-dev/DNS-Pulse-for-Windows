using System.Drawing;
using System.Windows.Forms;

namespace DnsPulse.App.Services;

public sealed class TrayNotificationService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly ToolStripMenuItem _statusItem;

    public event Action? OnRotateRequested;
    public event Action? OnDisconnectRequested;
    public event Action? OnShowWindowRequested;

    public TrayNotificationService()
    {
        _statusItem = new ToolStripMenuItem("DNS Pulse: Отключён") { Enabled = false };
        var rotateItem = new ToolStripMenuItem("Ротация ↻", null, (_, _) => OnRotateRequested?.Invoke());
        var stopItem = new ToolStripMenuItem("Откл", null, (_, _) => OnDisconnectRequested?.Invoke());
        var openItem = new ToolStripMenuItem("Открыть окно", null, (_, _) => OnShowWindowRequested?.Invoke());

        var menu = new ContextMenuStrip();
        menu.Items.Add(_statusItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(rotateItem);
        menu.Items.Add(stopItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(openItem);

        _notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Visible = true,
            Text = "DNS Pulse",
            ContextMenuStrip = menu
        };
        _notifyIcon.DoubleClick += (_, _) => OnShowWindowRequested?.Invoke();
    }

    public void UpdateActiveState(bool active, string? serverName, string? endpoint, string targetDomain, long queries)
    {
        if (!active)
        {
            _statusItem.Text = "DNS Pulse: Отключён";
            _notifyIcon.Text = "DNS Pulse • Отключён";
            return;
        }
        var summary = $"{serverName} • {targetDomain} • Запросов: {queries}";
        _statusItem.Text = $"{serverName} ({endpoint})";
        _notifyIcon.Text = summary.Length > 63 ? summary[..63] : summary;
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
    }
}
