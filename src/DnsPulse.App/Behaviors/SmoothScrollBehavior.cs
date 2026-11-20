using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace DnsPulse.App.Behaviors;

/// <summary>
/// Attached behavior providing fluid 60fps damped mouse-wheel scrolling for WPF <see cref="ScrollViewer"/>
/// and <see cref="ListView"/> controls, replacing Windows' harsh 3-line jump scroll.
/// </summary>
public static class SmoothScrollBehavior
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled",
        typeof(bool),
        typeof(SmoothScrollBehavior),
        new PropertyMetadata(false, OnIsEnabledChanged));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(SmoothScrollController),
        typeof(SmoothScrollBehavior),
        new PropertyMetadata(null));

    public static bool GetIsEnabled(DependencyObject obj)
    {
        ArgumentNullException.ThrowIfNull(obj);
        return (bool)obj.GetValue(IsEnabledProperty);
    }

    public static void SetIsEnabled(DependencyObject obj, bool value)
    {
        ArgumentNullException.ThrowIfNull(obj);
        obj.SetValue(IsEnabledProperty, value);
    }

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not UIElement element)
        {
            return;
        }

        if (element.GetValue(ControllerProperty) is SmoothScrollController existing)
        {
            existing.Detach();
            element.ClearValue(ControllerProperty);
        }

        if (e.NewValue is true)
        {
            SmoothScrollController controller = new(element);
            element.SetValue(ControllerProperty, controller);
        }
    }

    private sealed class SmoothScrollController
    {
        private const double PixelsPerWheelNotch = 54.0;
        private const double DampingPerFrame = 0.24;
        private const double SnapThresholdPixels = 0.45;

        private readonly UIElement _host;
        private ScrollViewer? _scrollViewer;
        private double _targetOffset;
        private double _currentOffset;
        private bool _isAnimating;

        public SmoothScrollController(UIElement host)
        {
            _host = host;
            _host.PreviewMouseWheel += OnPreviewMouseWheel;

            if (_host is FrameworkElement fe)
            {
                fe.Unloaded += OnUnloaded;
            }
        }

        public void Detach()
        {
            _host.PreviewMouseWheel -= OnPreviewMouseWheel;
            if (_host is FrameworkElement fe)
            {
                fe.Unloaded -= OnUnloaded;
            }

            StopAnimation();
            _scrollViewer = null;
        }

        private void OnUnloaded(object sender, RoutedEventArgs e)
        {
            StopAnimation();
        }

        private void OnPreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (e.Handled || Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
            {
                return;
            }

            ScrollViewer? viewer = ResolveScrollViewer();
            if (viewer is null || viewer.ScrollableHeight <= 0.5)
            {
                return;
            }

            // Do not hijack scrolling when the mouse is inside a nested scrollable control (e.g., multiline TextBox or ListView)
            // that has its own remaining scroll range in the wheel direction.
            if (e.OriginalSource is DependencyObject source && HasInnerScrollableViewer(source, viewer, e.Delta))
            {
                return;
            }

            double deltaPixels = -(e.Delta / 120.0) * PixelsPerWheelNotch;
            if (!SystemParameters.ClientAreaAnimation)
            {
                double immediate = Math.Clamp(viewer.VerticalOffset + deltaPixels, 0.0, viewer.ScrollableHeight);
                viewer.ScrollToVerticalOffset(immediate);
                e.Handled = true;
                return;
            }

            if (!_isAnimating)
            {
                _currentOffset = viewer.VerticalOffset;
                _targetOffset = _currentOffset;
            }

            _targetOffset = Math.Clamp(_targetOffset + deltaPixels, 0.0, viewer.ScrollableHeight);
            e.Handled = true;

            if (!_isAnimating)
            {
                _isAnimating = true;
                CompositionTarget.Rendering += OnCompositionTargetRendering;
            }
        }

        private void OnCompositionTargetRendering(object? sender, EventArgs e)
        {
            ScrollViewer? viewer = _scrollViewer;
            if (viewer is null || !viewer.IsVisible || viewer.ScrollableHeight <= 0.5)
            {
                StopAnimation();
                return;
            }

            // If user dragged the scrollbar thumb manually, yield immediately.
            if (Math.Abs(viewer.VerticalOffset - _currentOffset) > 4.0)
            {
                StopAnimation();
                return;
            }

            double remaining = _targetOffset - _currentOffset;
            if (Math.Abs(remaining) <= SnapThresholdPixels)
            {
                _currentOffset = _targetOffset;
                viewer.ScrollToVerticalOffset(_currentOffset);
                StopAnimation();
                return;
            }

            _currentOffset += remaining * DampingPerFrame;
            _currentOffset = Math.Clamp(_currentOffset, 0.0, viewer.ScrollableHeight);
            viewer.ScrollToVerticalOffset(_currentOffset);
        }

        private void StopAnimation()
        {
            if (_isAnimating)
            {
                _isAnimating = false;
                CompositionTarget.Rendering -= OnCompositionTargetRendering;
            }
        }

        private ScrollViewer? ResolveScrollViewer()
        {
            if (_scrollViewer is not null)
            {
                return _scrollViewer;
            }

            if (_host is ScrollViewer directViewer)
            {
                _scrollViewer = directViewer;
                return directViewer;
            }

            _scrollViewer = FindDescendantScrollViewer(_host);
            return _scrollViewer;
        }

        private static bool HasInnerScrollableViewer(DependencyObject source, ScrollViewer outer, int delta)
        {
            DependencyObject? current = source;
            while (current is not null && !ReferenceEquals(current, outer))
            {
                if (current is ScrollViewer inner && inner.ScrollableHeight > 0.5)
                {
                    bool scrollingDown = delta < 0;
                    if ((scrollingDown && inner.VerticalOffset < inner.ScrollableHeight - 0.5)
                        || (!scrollingDown && inner.VerticalOffset > 0.5))
                    {
                        return true;
                    }
                }

                current = VisualTreeHelper.GetParent(current);
            }

            return false;
        }

        private static ScrollViewer? FindDescendantScrollViewer(DependencyObject root)
        {
            int count = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < count; i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(root, i);
                if (child is ScrollViewer viewer)
                {
                    return viewer;
                }

                ScrollViewer? nested = FindDescendantScrollViewer(child);
                if (nested is not null)
                {
                    return nested;
                }
            }

            return null;
        }
    }
}
