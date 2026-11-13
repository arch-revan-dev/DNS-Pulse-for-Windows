using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Markup;
using DnsPulse.App.Localization;

namespace DnsPulse.App.Converters;

/// <summary>
/// Thread-safe singleton proxy exposing the active <see cref="LocalizationService"/> indexer
/// so XAML <c>{conv:Localization Key}</c> bindings refresh automatically on <c>CultureChanged</c>.
/// </summary>
public sealed class LocalizationSource : INotifyPropertyChanged
{
    private readonly Lock _syncLock = new();
    private LocalizationService _service = new();

    private LocalizationSource()
    {
        _service.CultureChanged += OnServiceCultureChanged;
    }

    public static LocalizationSource Instance { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    [IndexerName("Item")]
    public string this[string key]
    {
        get
        {
            lock (_syncLock)
            {
                return _service[key];
            }
        }
    }

    public LocalizationService Service
    {
        get
        {
            lock (_syncLock)
            {
                return _service;
            }
        }
    }

    /// <summary>
    /// Attaches the application's DI-managed <see cref="LocalizationService"/> instance.
    /// </summary>
    public void Attach(LocalizationService service)
    {
        ArgumentNullException.ThrowIfNull(service);

        lock (_syncLock)
        {
            if (ReferenceEquals(_service, service))
            {
                return;
            }

            _service.CultureChanged -= OnServiceCultureChanged;
            _service = service;
            _service.CultureChanged += OnServiceCultureChanged;
        }

        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
    }

    private void OnServiceCultureChanged(object? sender, CultureChangedEventArgs e)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
    }
}

/// <summary>
/// Reactive XAML markup extension binding directly to <see cref="LocalizationSource.Instance"/>
/// so localized strings update immediately when the user switches languages.
/// </summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class LocalizationExtension : MarkupExtension
{
    public LocalizationExtension()
    {
    }

    public LocalizationExtension(string key)
    {
        Key = key;
    }

    [ConstructorArgument("key")]
    public string Key { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);

        if (string.IsNullOrWhiteSpace(Key))
        {
            return string.Empty;
        }

        System.Windows.Data.Binding binding = new($"[{Key}]")
        {
            Source = LocalizationSource.Instance,
            Mode = BindingMode.OneWay,
            FallbackValue = Key
        };

        if (serviceProvider.GetService(typeof(IProvideValueTarget)) is IProvideValueTarget target &&
            target.TargetObject is Setter)
        {
            return binding;
        }

        return binding.ProvideValue(serviceProvider);
    }
}
