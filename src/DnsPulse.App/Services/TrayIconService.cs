using System.Diagnostics.CodeAnalysis;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Windows.Forms;
using DnsPulse.App.Localization;
using DnsPulse.Platform.Windows.Autostart;

namespace DnsPulse.App.Services;

/// <summary>
/// Manages the Windows system tray <see cref="NotifyIcon"/> (<c>Assets/app.ico</c>) and localized context menu
/// (<c>Connect / Disconnect</c>, <c>Rotate Upstream</c>, <c>Emergency Network Restore</c>, <c>Open PulseCore</c>, <c>Exit</c>).
/// </summary>
public sealed class TrayIconService : IDisposable
{
    private readonly LocalizationService _localization;
    private NotifyIcon? _notifyIcon;
    private ContextMenuStrip? _contextMenu;
    private ToolStripMenuItem? _connectDisconnectItem;
    private ToolStripMenuItem? _rotateItem;
    private ToolStripSeparator? _separator1;
    private ToolStripMenuItem? _emergencyRestoreItem;
    private ToolStripSeparator? _separator2;
    private ToolStripMenuItem? _openItem;
    private ToolStripMenuItem? _exitItem;
    private Icon? _ownedIcon;
    private bool _isConnected;
    private bool _disposed;

    public TrayIconService(LocalizationService localization)
    {
        ArgumentNullException.ThrowIfNull(localization);
        _localization = localization;
        _localization.CultureChanged += OnCultureChanged;
    }

    public event EventHandler? ConnectDisconnectRequested;

    public event EventHandler? RotateUpstreamRequested;

    public event EventHandler? EmergencyRestoreRequested;

    public event EventHandler? OpenWindowRequested;

    public event EventHandler? ExitRequested;

    public bool IsInitialized => _notifyIcon is not null;

    /// <summary>
    /// Creates and displays the system tray icon and context menu.
    /// </summary>
    public void Initialize()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_notifyIcon is not null)
        {
            return;
        }

        _ownedIcon = LoadTrayIcon();

        _connectDisconnectItem = new ToolStripMenuItem();
        _connectDisconnectItem.Click += (_, _) => ConnectDisconnectRequested?.Invoke(this, EventArgs.Empty);

        _rotateItem = new ToolStripMenuItem();
        _rotateItem.Click += (_, _) => RotateUpstreamRequested?.Invoke(this, EventArgs.Empty);

        _emergencyRestoreItem = new ToolStripMenuItem();
        _emergencyRestoreItem.Click += (_, _) => EmergencyRestoreRequested?.Invoke(this, EventArgs.Empty);

        _openItem = new ToolStripMenuItem();
        _openItem.Click += (_, _) => OpenWindowRequested?.Invoke(this, EventArgs.Empty);

        _exitItem = new ToolStripMenuItem();
        _exitItem.Click += (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty);

        _separator1 = new ToolStripSeparator();
        _separator2 = new ToolStripSeparator();

        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.AddRange(
        [
            _connectDisconnectItem,
            _rotateItem,
            _separator1,
            _emergencyRestoreItem,
            _separator2,
            _openItem,
            _exitItem
        ]);

        _notifyIcon = new NotifyIcon
        {
            Icon = _ownedIcon,
            ContextMenuStrip = _contextMenu,
            Visible = true
        };
        _notifyIcon.DoubleClick += (_, _) => OpenWindowRequested?.Invoke(this, EventArgs.Empty);

        RefreshLocalizedLabels(null);
    }

    /// <summary>
    /// Updates connection state reflected in the tray toggle label and tooltip.
    /// </summary>
    public void UpdateConnectionState(bool isConnected, string? statusDetail = null)
    {
        _isConnected = isConnected;
        RefreshLocalizedLabels(statusDetail);
    }

    /// <summary>
    /// Determines whether the main window should start hidden in the system tray.
    /// </summary>
    public static bool ShouldStartMinimized(PulseAppSettings settings, CliLaunchOptions cliOptions)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(cliOptions);

        return cliOptions.Minimized || (cliOptions.Autostart && settings.StartMinimizedToTray);
    }

    /// <summary>
    /// Determines whether closing the main window should hide to the tray instead of exiting.
    /// </summary>
    public static bool ShouldMinimizeToTrayOnClose(PulseAppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return settings.MinimizeToTrayOnClose;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _localization.CultureChanged -= OnCultureChanged;

        if (_notifyIcon is not null)
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _notifyIcon = null;
        }

        _connectDisconnectItem?.Dispose();
        _connectDisconnectItem = null;
        _rotateItem?.Dispose();
        _rotateItem = null;
        _separator1?.Dispose();
        _separator1 = null;
        _emergencyRestoreItem?.Dispose();
        _emergencyRestoreItem = null;
        _separator2?.Dispose();
        _separator2 = null;
        _openItem?.Dispose();
        _openItem = null;
        _exitItem?.Dispose();
        _exitItem = null;

        _contextMenu?.Dispose();
        _contextMenu = null;

        _ownedIcon?.Dispose();
        _ownedIcon = null;
    }

    private void OnCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        RefreshLocalizedLabels(null);
    }

    private void RefreshLocalizedLabels(string? statusDetail)
    {
        if (_connectDisconnectItem is not null)
        {
            _connectDisconnectItem.Text = _isConnected
                ? _localization["Tray_Disconnect"]
                : _localization["Tray_Connect"];
        }

        if (_rotateItem is not null)
        {
            _rotateItem.Text = _localization["Tray_RotateUpstream"];
        }

        if (_emergencyRestoreItem is not null)
        {
            _emergencyRestoreItem.Text = _localization["Tray_EmergencyRestore"];
        }

        if (_openItem is not null)
        {
            _openItem.Text = _localization["Tray_Open"];
        }

        if (_exitItem is not null)
        {
            _exitItem.Text = _localization["Tray_Exit"];
        }

        if (_notifyIcon is not null)
        {
            string stateText = _isConnected
                ? _localization["Overview_State_Protected"]
                : _localization["Overview_State_Disconnected"];

            string rawTip = string.IsNullOrWhiteSpace(statusDetail)
                ? string.Create(CultureInfo.InvariantCulture, $"{_localization["App_Title"]} — {stateText}")
                : string.Create(CultureInfo.InvariantCulture, $"{_localization["App_Title"]} — {statusDetail}");

            // NotifyIcon.Text has a hard 63-character limit on Windows.
            _notifyIcon.Text = rawTip.Length <= 63 ? rawTip : rawTip[..63];
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Icon loading falls back gracefully across WPF pack URI, disk asset, and executable icon.")]
    private static Icon LoadTrayIcon()
    {
        string diskIconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");
        if (File.Exists(diskIconPath))
        {
            try
            {
                return new Icon(diskIconPath);
            }
            catch (Exception)
            {
            }
        }

        try
        {
            Uri packUri = new("pack://application:,,,/Assets/app.ico", UriKind.Absolute);
            System.Windows.Resources.StreamResourceInfo? resourceInfo = System.Windows.Application.GetResourceStream(packUri);
            if (resourceInfo is not null)
            {
                using Stream stream = resourceInfo.Stream;
                return new Icon(stream);
            }
        }
        catch (Exception)
        {
        }

        string? processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath) && File.Exists(processPath))
        {
            try
            {
                Icon? associated = Icon.ExtractAssociatedIcon(processPath);
                if (associated is not null)
                {
                    return associated;
                }
            }
            catch (Exception)
            {
            }
        }

        return (Icon)SystemIcons.Shield.Clone();
    }
}
