using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace DnsPulse.App.Services;

public sealed class TrayNotificationService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly ToolStripMenuItem _statusItem;
    private readonly Icon? _customIcon;

    public event Action? OnAutoConnectRequested;
    public event Action? OnRotateRequested;
    public event Action? OnDisconnectRequested;
    public event Action? OnShowWindowRequested;
    public event Action? OnExitRequested;

    public TrayNotificationService()
    {
        _customIcon = LoadAppIcon();
        _statusItem = new ToolStripMenuItem("DNS Pulse: Отключён") { Enabled = false };
        var autoItem = new ToolStripMenuItem("Авторежим (подобрать и подключить) ⚡", null, (_, _) => OnAutoConnectRequested?.Invoke());
        var rotateItem = new ToolStripMenuItem("Ротация ↻", null, (_, _) => OnRotateRequested?.Invoke());
        var stopItem = new ToolStripMenuItem("Откл", null, (_, _) => OnDisconnectRequested?.Invoke());
        var openItem = new ToolStripMenuItem("Открыть окно", null, (_, _) => OnShowWindowRequested?.Invoke());
        var exitItem = new ToolStripMenuItem("Выход (закрыть процесс)", null, (_, _) => OnExitRequested?.Invoke());

        var menu = new ContextMenuStrip();
        menu.Items.Add(_statusItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(autoItem);
        menu.Items.Add(rotateItem);
        menu.Items.Add(stopItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(openItem);
        menu.Items.Add(exitItem);

        _notifyIcon = new NotifyIcon
        {
            Icon = _customIcon ?? SystemIcons.Shield,
            Visible = true,
            Text = "DNS Pulse",
            ContextMenuStrip = menu
        };
        _notifyIcon.DoubleClick += (_, _) => OnShowWindowRequested?.Invoke();
    }

    private static Icon? LoadAppIcon()
    {
        try
        {
            var streamInfo = System.Windows.Application.GetResourceStream(
                new Uri("pack://application:,,,/Assets/app.ico", UriKind.Absolute));
            if (streamInfo?.Stream is not null)
            {
                using var s = streamInfo.Stream;
                return new Icon(s);
            }
        }
        catch
        {
            // Fall through to executable icon
        }

        try
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(exe) && File.Exists(exe))
                return Icon.ExtractAssociatedIcon(exe);
        }
        catch
        {
            // Fallback to SystemIcons.Shield
        }

        return null;
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

    public void ShowTrayBalloon(string title, string message, int timeoutMs = 2400)
    {
        try
        {
            _notifyIcon.ShowBalloonTip(timeoutMs, title, message, ToolTipIcon.Info);
        }
        catch
        {
            // Non-fatal on restricted notification shells
        }
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _customIcon?.Dispose();
    }
}
