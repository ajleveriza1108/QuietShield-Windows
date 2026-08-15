using System.Runtime.InteropServices;

namespace QuietShield.App.Windowing;

internal static class MaximizedWorkAreaWindowHook
{
    internal const int WmGetMinMaxInfo = 0x0024;
    private const uint MonitorDefaultToNearest = 0x00000002;

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
    private struct NativeMinMaxInfo
    {
        public NativePoint Reserved;
        public NativePoint MaxSize;
        public NativePoint MaxPosition;
        public NativePoint MinTrackSize;
        public NativePoint MaxTrackSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeMonitorInfo
    {
        public uint Size;
        public NativeRect Monitor;
        public NativeRect Work;
        public uint Flags;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(
        IntPtr window,
        uint flags);

    [DllImport(
        "user32.dll",
        CharSet = CharSet.Auto,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfo(
        IntPtr monitor,
        ref NativeMonitorInfo monitorInfo);

    internal static bool TryHandle(
        IntPtr window,
        int message,
        IntPtr lParam)
    {
        if (message != WmGetMinMaxInfo || lParam == IntPtr.Zero)
        {
            return false;
        }

        var monitor = MonitorFromWindow(
            window,
            MonitorDefaultToNearest);

        if (monitor == IntPtr.Zero)
        {
            return false;
        }

        var monitorInfo = new NativeMonitorInfo
        {
            Size = (uint)Marshal.SizeOf<NativeMonitorInfo>()
        };

        if (!GetMonitorInfo(monitor, ref monitorInfo))
        {
            return false;
        }

        var info = Marshal.PtrToStructure<NativeMinMaxInfo>(lParam);

        var work = monitorInfo.Work;
        var monitorBounds = monitorInfo.Monitor;

        info.MaxPosition.X = work.Left - monitorBounds.Left;
        info.MaxPosition.Y = work.Top - monitorBounds.Top;
        info.MaxSize.X = work.Right - work.Left;
        info.MaxSize.Y = work.Bottom - work.Top;
        info.MaxTrackSize.X = info.MaxSize.X;
        info.MaxTrackSize.Y = info.MaxSize.Y;

        Marshal.StructureToPtr(
            info,
            lParam,
            false);

        return true;
    }
}
