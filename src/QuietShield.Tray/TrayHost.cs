// QuietShield Backend Integration 11 R1
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;

namespace QuietShield.Tray;

public sealed class TrayHost : IDisposable
{
    private const int CallbackMessage = 0x8001;
    private const int WmLeftButtonUp = 0x0202;
    private const int WmRightButtonUp = 0x0205;
    private const uint NimAdd = 0;
    private const uint NimDelete = 2;
    private const uint NifMessage = 1;
    private const uint NifIcon = 2;
    private const uint NifTip = 4;

    private static readonly IntPtr DefaultApplicationIcon = new(32512);

    private HwndSource? _source;
    private ContextMenu? _menu;
    private NotifyIconData _data;
    private bool _added;

    public void Initialize()
    {
        if (_added)
            return;

        var parameters = new HwndSourceParameters("QuietShield.Tray.Hidden")
        {
            Width = 0,
            Height = 0,
            WindowStyle = 0
        };

        _source = new HwndSource(parameters);
        _source.AddHook(WindowProcedure);

        var icon = LoadIcon(IntPtr.Zero, DefaultApplicationIcon);
        if (icon == IntPtr.Zero)
            throw new InvalidOperationException("Windows did not provide a tray icon.");

        _data = new NotifyIconData
        {
            Size = (uint)Marshal.SizeOf<NotifyIconData>(),
            WindowHandle = _source.Handle,
            Id = 1,
            Flags = NifMessage | NifIcon | NifTip,
            CallbackMessage = CallbackMessage,
            IconHandle = icon,
            ToolTip = "QuietShield Windows",
            Info = string.Empty,
            InfoTitle = string.Empty
        };

        if (!ShellNotifyIcon(NimAdd, ref _data))
            throw new InvalidOperationException("Windows rejected the QuietShield tray icon.");

        _added = true;
        BuildMenu();
    }

    public void Dispose()
    {
        if (_added)
        {
            _ = ShellNotifyIcon(NimDelete, ref _data);
            _added = false;
        }

        if (_source is not null)
        {
            _source.RemoveHook(WindowProcedure);
            _source.Dispose();
            _source = null;
        }

        _menu = null;
        GC.SuppressFinalize(this);
    }

    private void BuildMenu()
    {
        var open = new MenuItem { Header = "Open QuietShield" };
        open.Click += (_, _) => OpenQuietShield();

        var browser = new MenuItem { Header = "Private Browser" };
        browser.Click += (_, _) => OpenPrivateBrowser();

        var exit = new MenuItem { Header = "Exit Tray" };
        exit.Click += (_, _) => System.Windows.Application.Current.Shutdown();

        _menu = new ContextMenu
        {
            Placement = PlacementMode.MousePoint
        };

        _menu.Items.Add(open);
        _menu.Items.Add(browser);
        _menu.Items.Add(new Separator());
        _menu.Items.Add(exit);
    }

    private IntPtr WindowProcedure(
        IntPtr hwnd,
        int message,
        IntPtr wParam,
        IntPtr lParam,
        ref bool handled)
    {
        if (message != CallbackMessage)
            return IntPtr.Zero;

        var trayMessage = unchecked((int)lParam.ToInt64());

        if (trayMessage == WmLeftButtonUp)
        {
            OpenQuietShield();
            handled = true;
        }
        else if (trayMessage == WmRightButtonUp)
        {
            if (_menu is not null)
                _menu.IsOpen = true;

            handled = true;
        }

        return IntPtr.Zero;
    }

    private static void OpenQuietShield()
    {
        const string path =
            @"D:\Windows Projects\QuietShield-Windows\artifacts\bin\QuietShield.App\x64\Release\net10.0-windows\QuietShield.App.exe";

        if (File.Exists(path))
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
    }

    private static void OpenPrivateBrowser()
    {
        const string path =
            @"D:\Windows Projects\QuietShield-Windows\artifacts\bin\QuietShield.PrivateBrowser\Release\net10.0-windows\QuietShield.PrivateBrowser.exe";

        if (File.Exists(path))
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
    }

#pragma warning disable SYSLIB1054
    [DllImport("shell32.dll", EntryPoint = "Shell_NotifyIconW", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShellNotifyIcon(uint message, ref NotifyIconData data);

    [DllImport("user32.dll", EntryPoint = "LoadIconW", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadIcon(IntPtr instance, IntPtr iconName);
#pragma warning restore SYSLIB1054

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint Size;
        public IntPtr WindowHandle;
        public uint Id;
        public uint Flags;
        public uint CallbackMessage;
        public IntPtr IconHandle;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string ToolTip;

        public uint State;
        public uint StateMask;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Info;

        public uint TimeoutOrVersion;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string InfoTitle;

        public uint InfoFlags;
        public Guid ItemGuid;
        public IntPtr BalloonIconHandle;
    }
}
