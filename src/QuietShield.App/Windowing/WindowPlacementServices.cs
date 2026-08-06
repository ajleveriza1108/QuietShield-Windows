using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using QuietShield.Core.Presentation;

namespace QuietShield.App.Windowing;

public interface IWindowPlacementStore
{
    SavedWindowPlacement? Load();
    void Save(SavedWindowPlacement placement);
}

public sealed class JsonWindowPlacementStore(string path) : IWindowPlacementStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    public SavedWindowPlacement? Load()
    {
        try
        {
            return File.Exists(path)
                ? JsonSerializer.Deserialize<SavedWindowPlacement>(File.ReadAllText(path), SerializerOptions)
                : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public void Save(SavedWindowPlacement placement)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            var temporaryPath = path + ".tmp";
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(placement, SerializerOptions));
            File.Move(temporaryPath, path, true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Window placement is a convenience only; startup and shutdown must never fail because it cannot be persisted.
        }
    }
}

public sealed class InMemoryWindowPlacementStore : IWindowPlacementStore
{
    private SavedWindowPlacement? _placement;

    public SavedWindowPlacement? Load() => _placement;
    public void Save(SavedWindowPlacement placement) => _placement = placement;
}

public interface IDisplayWorkAreaProvider
{
    IReadOnlyList<UiRect> GetWorkAreas();
}

public sealed class WindowsDisplayWorkAreaProvider : IDisplayWorkAreaProvider
{
    public IReadOnlyList<UiRect> GetWorkAreas()
    {
        var result = new List<UiRect>();
        MonitorEnumProc callback = (monitor, _, _, _) =>
        {
            var information = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
            if (GetMonitorInfo(monitor, ref information))
            {
                result.Add(new UiRect(
                    information.Work.Left,
                    information.Work.Top,
                    information.Work.Right - information.Work.Left,
                    information.Work.Bottom - information.Work.Top));
            }
            return true;
        };

        if (!EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, callback, IntPtr.Zero) || result.Count == 0)
        {
            var fallback = SystemParameters.WorkArea;
            result.Add(new UiRect(fallback.Left, fallback.Top, fallback.Width, fallback.Height));
        }

        GC.KeepAlive(callback);
        return result;
    }

    private delegate bool MonitorEnumProc(IntPtr monitor, IntPtr deviceContext, IntPtr monitorRectangle, IntPtr data);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MonitorInfo
    {
        public int Size;
        public NativeRect Monitor;
        public NativeRect Work;
        public uint Flags;
    }

    [SuppressMessage("Interoperability", "SYSLIB1054:Use LibraryImportAttribute instead of DllImportAttribute", Justification = "A managed callback delegate is required for monitor enumeration.")]
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplayMonitors(IntPtr deviceContext, IntPtr clipRectangle, MonitorEnumProc callback, IntPtr data);

    [SuppressMessage("Interoperability", "SYSLIB1054:Use LibraryImportAttribute instead of DllImportAttribute", Justification = "The native monitor information structure is simple and fixed.")]
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo information);
}

public static class WindowPlacementCoordinator
{
    public static void Restore(Window window, IWindowPlacementStore store, IDisplayWorkAreaProvider workAreas)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(workAreas);

        var saved = store.Load();
        if (saved is null) return;
        var dpi = VisualTreeHelper.GetDpi(window);
        var constrained = ResponsiveLayout.ConstrainWindowPlacement(
            saved.Value,
            workAreas.GetWorkAreas(),
            new UiSize(window.MinWidth * dpi.DpiScaleX, window.MinHeight * dpi.DpiScaleY));
        var native = new NativeWindowPlacement
        {
            Size = Marshal.SizeOf<NativeWindowPlacement>(),
            ShowCommand = constrained.IsMaximized ? ShowMaximized : ShowNormal,
            NormalPosition = new NativeRect
            {
                Left = ToNativeCoordinate(constrained.Left),
                Top = ToNativeCoordinate(constrained.Top),
                Right = ToNativeCoordinate(constrained.Left + constrained.Width),
                Bottom = ToNativeCoordinate(constrained.Top + constrained.Height)
            }
        };
        if (!SetWindowPlacement(new WindowInteropHelper(window).Handle, ref native))
        {
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        }
    }

    public static void Save(Window window, IWindowPlacementStore store)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(store);

        var native = new NativeWindowPlacement { Size = Marshal.SizeOf<NativeWindowPlacement>() };
        if (!GetWindowPlacement(new WindowInteropHelper(window).Handle, ref native)) return;
        var bounds = native.NormalPosition;
        store.Save(new SavedWindowPlacement(
            bounds.Left, bounds.Top, bounds.Right - bounds.Left, bounds.Bottom - bounds.Top,
            window.WindowState == WindowState.Maximized));
    }

    public static void ConstrainDialogToOwnerWorkArea(Window dialog, Window owner, IDisplayWorkAreaProvider workAreas)
    {
        ArgumentNullException.ThrowIfNull(dialog);
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(workAreas);

        var ownerBounds = owner.WindowState == WindowState.Normal
            ? new UiRect(owner.Left, owner.Top, owner.Width, owner.Height)
            : new UiRect(owner.RestoreBounds.Left, owner.RestoreBounds.Top, owner.RestoreBounds.Width, owner.RestoreBounds.Height);
        var target = ResponsiveLayout.ConstrainWindowPlacement(
            new SavedWindowPlacement(ownerBounds.Left, ownerBounds.Top, ownerBounds.Width, ownerBounds.Height, false),
            workAreas.GetWorkAreas(),
            new UiSize(1d, 1d));
        var size = ResponsiveLayout.ConstrainDialogSize(
            new UiSize(dialog.Width, dialog.Height),
            new UiRect(target.Left, target.Top, target.Width, target.Height));
        dialog.MaxWidth = size.Width;
        dialog.MaxHeight = size.Height;
    }

    private const int ShowNormal = 1;
    private const int ShowMaximized = 3;

    private static int ToNativeCoordinate(double value) => checked((int)Math.Round(value, MidpointRounding.AwayFromZero));

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeWindowPlacement
    {
        public int Size;
        public int Flags;
        public int ShowCommand;
        public NativePoint MinimumPosition;
        public NativePoint MaximumPosition;
        public NativeRect NormalPosition;
    }

    [SuppressMessage("Interoperability", "SYSLIB1054:Use LibraryImportAttribute instead of DllImportAttribute", Justification = "WINDOWPLACEMENT is a fixed Win32 structure used only for safe window restoration.")]
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowPlacement(IntPtr window, ref NativeWindowPlacement placement);

    [SuppressMessage("Interoperability", "SYSLIB1054:Use LibraryImportAttribute instead of DllImportAttribute", Justification = "WINDOWPLACEMENT is a fixed Win32 structure used only for safe window restoration.")]
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPlacement(IntPtr window, [In] ref NativeWindowPlacement placement);
}
