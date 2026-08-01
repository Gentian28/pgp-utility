using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Styling;

namespace PgpUtility.App;

public partial class MainWindow : Window
{
    public MainWindow() => InitializeComponent();

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == ActualThemeVariantProperty)
            SyncTitleBarTheme();
    }

    // CenterScreen positions the window but never shrinks it. On a 1080p display at 150% scaling
    // the declared 960x720 logical size is taller than the screen, and centring a too-tall window
    // puts the title bar above the top edge, where it cannot be dragged, closed or reached at all.
    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        FitToWorkingArea();
        SyncTitleBarTheme();
    }

    // Avalonia paints the client area but the title bar belongs to Windows, and Avalonia only
    // matches it to the OS setting. Without this, choosing Light while Windows is in dark mode
    // leaves a dark bar over a light window. macOS and Linux draw their own chrome correctly.
    private void SyncTitleBarTheme()
    {
        if (!OperatingSystem.IsWindows())
            return;

        if (TryGetPlatformHandle()?.Handle is not { } hwnd || hwnd == IntPtr.Zero)
            return;

        int dark = ActualThemeVariant == ThemeVariant.Dark ? 1 : 0;
        _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref dark, sizeof(int));
    }

    private const int DwmwaUseImmersiveDarkMode = 20;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private void FitToWorkingArea()
    {
        var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary;
        if (screen is null)
            return;

        // WorkingArea is in physical pixels; Width, Height and FrameSize are logical.
        var work = screen.WorkingArea;
        var scale = DesktopScaling;

        var frame = FrameSize ?? ClientSize;
        var chromeWidth = Math.Max(0, frame.Width - ClientSize.Width);
        var chromeHeight = Math.Max(0, frame.Height - ClientSize.Height);

        var maxWidth = work.Width / scale - chromeWidth;
        var maxHeight = work.Height / scale - chromeHeight;

        if (Width > maxWidth)
            Width = Math.Max(MinWidth, maxWidth);
        if (Height > maxHeight)
            Height = Math.Max(MinHeight, maxHeight);

        var frameWidth = (Width + chromeWidth) * scale;
        var frameHeight = (Height + chromeHeight) * scale;
        Position = new PixelPoint(
            work.X + Math.Max(0, (int)((work.Width - frameWidth) / 2)),
            work.Y + Math.Max(0, (int)((work.Height - frameHeight) / 2)));
    }
}
