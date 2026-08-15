using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using QuietShield.App.Runtime;
using QuietShield.App.ViewModels;

namespace QuietShield.App.Tray;

public sealed class QuietShieldTrayIcon : IDisposable
{
    private const int TrayCallbackMessage = 0x8001;
    private const int WmLeftButtonUp = 0x0202;
    private const int WmRightButtonUp = 0x0205;
    private const uint NotifyIconId = 1;
    private const uint NotifyIconAdd = 0x00000000;
    private const uint NotifyIconModify = 0x00000001;
    private const uint NotifyIconDelete = 0x00000002;
    private const uint NotifyIconMessage = 0x00000001;
    private const uint NotifyIconIcon = 0x00000002;
    private const uint NotifyIconTip = 0x00000004;
    private const uint ImageIcon = 1;
    private const uint LoadFromFile = 0x00000010;
    private const uint LoadDefaultSize = 0x00000040;

    private MainWindow? _window;
    private MainViewModel? _viewModel;
    private Action? _requestExit;
    private HwndSource? _source;
    private ContextMenu? _contextMenu;
    private MenuItem? _statusItem;
    private MenuItem? _openItem;
    private MenuItem? _protectionItem;
    private MenuItem? _dataSavingItem;
    private MenuItem? _wiFiItem;
    private MenuItem? _privateBrowserItem;
    private MenuItem? _fileSafetyItem;
    private MenuItem? _activityItem;
    private MenuItem? _exitItem;
    private NotifyIconData _notifyData;
    private IntPtr _ownedIconHandle;
    private bool _iconAdded;

    public bool IsAvailable => _iconAdded;

    public string LastInitializationMessage { get; private set; } =
        "Tray initialization has not run.";

    public bool Initialize(
        MainWindow window,
        MainViewModel viewModel,
        Action requestExit)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(viewModel);
        ArgumentNullException.ThrowIfNull(requestExit);

        if (_iconAdded)
        {
            window.CloseToTrayEnabled = true;
            return true;
        }

        window.CloseToTrayEnabled = false;
        _window = window;
        _viewModel = viewModel;
        _requestExit = requestExit;

        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero)
        {
            return FailInitialization(
                "QuietShield could not obtain its WPF window handle.");
        }

        _source = HwndSource.FromHwnd(handle);
        if (_source is null)
        {
            return FailInitialization(
                "QuietShield could not attach a tray callback to the WPF window.");
        }

        try
        {
            _source.AddHook(WindowProcedure);
            BuildContextMenu();
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or ArgumentException)
        {
            return FailInitialization(
                "WPF rejected the notification-area callback or menu.",
                exception);
        }

        var iconPath = Path.Combine(
            AppContext.BaseDirectory,
            "Assets",
            "QuietShield_Tray.ico");

        _ownedIconHandle = LoadImage(
            IntPtr.Zero,
            iconPath,
            ImageIcon,
            0,
            0,
            LoadFromFile | LoadDefaultSize);

        if (_ownedIconHandle == IntPtr.Zero)
        {
            return FailInitialization(
                "QuietShield could not load its supplied notification-area logo: " +
                iconPath);
        }

        _notifyData = new NotifyIconData
        {
            Size = (uint)Marshal.SizeOf<NotifyIconData>(),
            WindowHandle = handle,
            Id = NotifyIconId,
            Flags = NotifyIconMessage | NotifyIconIcon | NotifyIconTip,
            CallbackMessage = TrayCallbackMessage,
            IconHandle = _ownedIconHandle,
            ToolTip = "QuietShield Windows",
            Info = string.Empty,
            InfoTitle = string.Empty
        };

        bool added;
        try
        {
            added = ShellNotifyIcon(NotifyIconAdd, ref _notifyData);
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or
            EntryPointNotFoundException or
            ExternalException)
        {
            return FailInitialization(
                "Windows notification-area registration failed.",
                exception);
        }

        if (!added)
        {
            return FailInitialization(
                "Windows rejected the QuietShield notification-area icon. Win32 error=" +
                Marshal.GetLastPInvokeError().ToString(
                    System.Globalization.CultureInfo.InvariantCulture));
        }

        _iconAdded = true;
        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        UpdatePresentation();

        LastInitializationMessage =
            "QuietShield notification-area logo and consumer menu are active.";

        IntegrationRuntimeDiagnostics.WriteMessage(
            "Tray",
            LastInitializationMessage);

        window.CloseToTrayEnabled = true;
        return true;
    }

    public void Dispose()
    {
        if (_viewModel is not null)
        {
            _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        if (_iconAdded)
        {
            TryDeleteNativeIcon();
            _iconAdded = false;
        }

        RemoveHook();
        RemoveMenuHandlers();

        if (_contextMenu is not null)
        {
            _contextMenu.IsOpen = false;
        }

        _contextMenu = null;
        _statusItem = null;
        _openItem = null;
        _protectionItem = null;
        _dataSavingItem = null;
        _wiFiItem = null;
        _privateBrowserItem = null;
        _fileSafetyItem = null;
        _activityItem = null;
        _exitItem = null;

        if (_window is not null)
        {
            _window.CloseToTrayEnabled = false;
        }

        if (_ownedIconHandle != IntPtr.Zero)
        {
            _ = DestroyIcon(_ownedIconHandle);
            _ownedIconHandle = IntPtr.Zero;
        }

        _window = null;
        _viewModel = null;
        _requestExit = null;

        GC.SuppressFinalize(this);
    }

    private bool FailInitialization(
        string message,
        Exception? exception = null)
    {
        LastInitializationMessage = message;

        if (exception is null)
        {
            IntegrationRuntimeDiagnostics.WriteMessage("Tray", message);
        }
        else
        {
            IntegrationRuntimeDiagnostics.WriteException(
                "Tray",
                message,
                exception);
        }

        _iconAdded = false;
        RemoveHook();
        RemoveMenuHandlers();

        if (_contextMenu is not null)
        {
            _contextMenu.IsOpen = false;
        }

        if (_window is not null)
        {
            _window.CloseToTrayEnabled = false;
        }

        if (_ownedIconHandle != IntPtr.Zero)
        {
            _ = DestroyIcon(_ownedIconHandle);
            _ownedIconHandle = IntPtr.Zero;
        }

        return false;
    }

    private void BuildContextMenu()
    {
        _statusItem = CreateMenuItem(
            "Protection status",
            enabled: false,
            icon: CreateLogoImage());

        _openItem = CreateMenuItem(
            "Open QuietShield",
            icon: CreateLogoImage());

        _protectionItem = CreateMenuItem("Turn Protection On");
        _dataSavingItem = CreateMenuItem("Data Saving Mode");
        _wiFiItem = CreateMenuItem("Wi-Fi Mode");
        _privateBrowserItem = CreateMenuItem("Private Browser");
        _fileSafetyItem = CreateMenuItem("File Safety");
        _activityItem = CreateMenuItem("Activity");
        _exitItem = CreateMenuItem("Exit QuietShield");

        _openItem.Click += OnOpenClick;
        _protectionItem.Click += OnProtectionClick;
        _dataSavingItem.Click += OnDataSavingClick;
        _wiFiItem.Click += OnWiFiClick;
        _privateBrowserItem.Click += OnPrivateBrowserClick;
        _fileSafetyItem.Click += OnFileSafetyClick;
        _activityItem.Click += OnActivityClick;
        _exitItem.Click += OnExitClick;

        _contextMenu = new ContextMenu
        {
            Placement = PlacementMode.MousePoint,
            Style = System.Windows.Application.Current.TryFindResource(
                "TrayContextMenuStyle") as System.Windows.Style
        };

        _contextMenu.Items.Add(_statusItem);
        _contextMenu.Items.Add(CreateSeparator());
        _contextMenu.Items.Add(_openItem);
        _contextMenu.Items.Add(_protectionItem);
        _contextMenu.Items.Add(CreateSeparator());
        _contextMenu.Items.Add(_dataSavingItem);
        _contextMenu.Items.Add(_wiFiItem);
        _contextMenu.Items.Add(CreateSeparator());
        _contextMenu.Items.Add(_privateBrowserItem);
        _contextMenu.Items.Add(_fileSafetyItem);
        _contextMenu.Items.Add(_activityItem);
        _contextMenu.Items.Add(CreateSeparator());
        _contextMenu.Items.Add(_exitItem);
            ApplyDarkTrayThemeR364(_contextMenu);
}

    private static MenuItem CreateMenuItem(
        string header,
        bool enabled = true,
        object? icon = null)
    {
        return new MenuItem
        {
            Header = header,
            IsEnabled = enabled,
            Icon = icon,
            Style = System.Windows.Application.Current.TryFindResource(
                "TrayMenuItemStyle") as System.Windows.Style
        };
    }

    private static Separator CreateSeparator() =>
        new()
        {
            Style = System.Windows.Application.Current.TryFindResource(
                "TraySeparatorStyle") as System.Windows.Style
        };

    private static Image? CreateLogoImage()
    {
        try
        {
            var image = new Image
            {
                Width = 18,
                Height = 18,
                Stretch = System.Windows.Media.Stretch.Uniform
            };

            image.Source = new BitmapImage(
                new Uri(
                    "pack://application:,,,/QuietShield.App;component/Assets/QuietShield_UI.png",
                    UriKind.Absolute));

            return image;
        }
        catch
        {
            return null;
        }
    }

    private static void ApplyDarkTrayThemeR3631(
        ContextMenu menu)
    {
        const string themeXaml = @"<ResourceDictionary
 xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
 xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"">
 <SolidColorBrush x:Key=""TraySurface"" Color=""#0A1B2F""/>
 <SolidColorBrush x:Key=""TrayRaised"" Color=""#14304F""/>
 <SolidColorBrush x:Key=""TrayAccent"" Color=""#3399FF""/>
 <SolidColorBrush x:Key=""TrayDivider"" Color=""#36587A""/>
 <SolidColorBrush x:Key=""TrayMuted"" Color=""#7E91A8""/>

 <Style TargetType=""{x:Type MenuItem}"">
   <Setter Property=""Foreground"" Value=""White""/>
   <Setter Property=""Background"" Value=""{StaticResource TraySurface}""/>
   <Setter Property=""FontFamily"" Value=""Segoe UI""/>
   <Setter Property=""FontSize"" Value=""14""/>
   <Setter Property=""MinHeight"" Value=""38""/>
   <Setter Property=""Padding"" Value=""0""/>
   <Setter Property=""BorderThickness"" Value=""0""/>
   <Setter Property=""Template"">
     <Setter.Value>
       <ControlTemplate TargetType=""{x:Type MenuItem}"">
         <Border x:Name=""Root""
                 Background=""{TemplateBinding Background}""
                 SnapsToDevicePixels=""True"">
           <Grid MinHeight=""38"">
             <Grid.ColumnDefinitions>
               <ColumnDefinition Width=""38""/>
               <ColumnDefinition Width=""*""/>
             </Grid.ColumnDefinitions>

             <Grid Grid.Column=""0""
                   Background=""{TemplateBinding Background}"">
               <ContentPresenter Content=""{TemplateBinding Icon}""
                                 HorizontalAlignment=""Center""
                                 VerticalAlignment=""Center""/>
               <TextBlock x:Name=""CheckGlyph""
                          Text=""&#x2713;""
                          Foreground=""{StaticResource TrayAccent}""
                          FontWeight=""SemiBold""
                          FontSize=""14""
                          HorizontalAlignment=""Center""
                          VerticalAlignment=""Center""
                          Visibility=""Collapsed""/>
             </Grid>

             <ContentPresenter Grid.Column=""1""
                               ContentSource=""Header""
                               RecognizesAccessKey=""True""
                               VerticalAlignment=""Center""
                               Margin=""0,0,16,0""/>
           </Grid>
         </Border>

         <ControlTemplate.Triggers>
           <Trigger Property=""IsHighlighted"" Value=""True"">
             <Setter TargetName=""Root""
                     Property=""Background""
                     Value=""{StaticResource TrayRaised}""/>
           </Trigger>
           <Trigger Property=""IsChecked"" Value=""True"">
             <Setter TargetName=""CheckGlyph""
                     Property=""Visibility""
                     Value=""Visible""/>
           </Trigger>
           <Trigger Property=""IsEnabled"" Value=""False"">
             <Setter Property=""Foreground""
                     Value=""{StaticResource TrayMuted}""/>
           </Trigger>
         </ControlTemplate.Triggers>
       </ControlTemplate>
     </Setter.Value>
   </Setter>
 </Style>

 <Style TargetType=""{x:Type Separator}"">
   <Setter Property=""Margin"" Value=""12,5,12,5""/>
   <Setter Property=""Height"" Value=""1""/>
   <Setter Property=""Template"">
     <Setter.Value>
       <ControlTemplate TargetType=""{x:Type Separator}"">
         <Border Height=""1""
                 Background=""{StaticResource TrayDivider}""/>
       </ControlTemplate>
     </Setter.Value>
   </Setter>
 </Style>
</ResourceDictionary>";

        var resources =
            (System.Windows.ResourceDictionary)
            System.Windows.Markup.XamlReader.Parse(
                themeXaml);

        menu.Resources.MergedDictionaries.Add(
            resources);

        menu.Background =
            (System.Windows.Media.Brush)
            resources["TraySurface"];

        menu.Foreground =
            System.Windows.Media.Brushes.White;

        menu.BorderBrush =
            (System.Windows.Media.Brush)
            resources["TrayDivider"];

        menu.BorderThickness =
            new System.Windows.Thickness(1);

        menu.Padding =
            new System.Windows.Thickness(
                0,
                4,
                0,
                4);

        menu.HasDropShadow = true;
    }
    private static void ApplyDarkTrayThemeR364(
        ContextMenu menu)
    {
        const string themeXaml = @"<ResourceDictionary
 xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
 xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"">

 <SolidColorBrush x:Key=""TraySurface"" Color=""#0A1B2F""/>
 <SolidColorBrush x:Key=""TrayRaised"" Color=""#16395C""/>
 <SolidColorBrush x:Key=""TrayAccent"" Color=""#3D9CFF""/>
 <SolidColorBrush x:Key=""TrayDivider"" Color=""#345572""/>
 <SolidColorBrush x:Key=""TrayMuted"" Color=""#91A5B8""/>

 <ControlTemplate x:Key=""QuietShieldTrayContextMenuTemplate""
                  TargetType=""{x:Type ContextMenu}"">
   <Border Background=""{TemplateBinding Background}""
           BorderBrush=""{TemplateBinding BorderBrush}""
           BorderThickness=""{TemplateBinding BorderThickness}""
           CornerRadius=""8""
           SnapsToDevicePixels=""True"">
     <ScrollViewer Background=""{TemplateBinding Background}""
                   HorizontalScrollBarVisibility=""Disabled""
                   VerticalScrollBarVisibility=""Auto""
                   CanContentScroll=""True"">
       <ItemsPresenter Margin=""0,4,0,4""/>
     </ScrollViewer>
   </Border>
 </ControlTemplate>

 <Style x:Key=""QuietShieldTrayMenuItemStyle""
        TargetType=""{x:Type MenuItem}"">
   <Setter Property=""Foreground"" Value=""White""/>
   <Setter Property=""Background"" Value=""{StaticResource TraySurface}""/>
   <Setter Property=""FontFamily"" Value=""Segoe UI""/>
   <Setter Property=""FontSize"" Value=""14""/>
   <Setter Property=""MinHeight"" Value=""38""/>
   <Setter Property=""Padding"" Value=""0""/>
   <Setter Property=""BorderThickness"" Value=""0""/>
   <Setter Property=""Template"">
     <Setter.Value>
       <ControlTemplate TargetType=""{x:Type MenuItem}"">
         <Border x:Name=""Root""
                 Background=""{TemplateBinding Background}""
                 SnapsToDevicePixels=""True"">
           <Grid MinHeight=""38"">
             <Grid.ColumnDefinitions>
               <ColumnDefinition Width=""38""/>
               <ColumnDefinition Width=""*""/>
             </Grid.ColumnDefinitions>

             <Grid x:Name=""MarkerHost""
                   Grid.Column=""0""
                   Background=""{TemplateBinding Background}"">
               <ContentPresenter Content=""{TemplateBinding Icon}""
                                 HorizontalAlignment=""Center""
                                 VerticalAlignment=""Center""/>
               <TextBlock x:Name=""CheckGlyph""
                          Text=""&#x2713;""
                          Foreground=""{StaticResource TrayAccent}""
                          FontSize=""14""
                          FontWeight=""SemiBold""
                          HorizontalAlignment=""Center""
                          VerticalAlignment=""Center""
                          Visibility=""Collapsed""/>
             </Grid>

             <ContentPresenter Grid.Column=""1""
                               ContentSource=""Header""
                               RecognizesAccessKey=""True""
                               VerticalAlignment=""Center""
                               Margin=""0,0,16,0""/>
           </Grid>
         </Border>

         <ControlTemplate.Triggers>
           <Trigger Property=""IsHighlighted"" Value=""True"">
             <Setter TargetName=""Root""
                     Property=""Background""
                     Value=""{StaticResource TrayRaised}""/>
             <Setter TargetName=""MarkerHost""
                     Property=""Background""
                     Value=""{StaticResource TrayRaised}""/>
           </Trigger>

           <Trigger Property=""IsChecked"" Value=""True"">
             <Setter TargetName=""CheckGlyph""
                     Property=""Visibility""
                     Value=""Visible""/>
           </Trigger>

           <Trigger Property=""IsEnabled"" Value=""False"">
             <Setter Property=""Foreground""
                     Value=""{StaticResource TrayMuted}""/>
           </Trigger>
         </ControlTemplate.Triggers>
       </ControlTemplate>
     </Setter.Value>
   </Setter>
 </Style>

 <Style x:Key=""QuietShieldTraySeparatorStyle""
        TargetType=""{x:Type Separator}"">
   <Setter Property=""Margin"" Value=""12,5,12,5""/>
   <Setter Property=""Height"" Value=""1""/>
   <Setter Property=""Template"">
     <Setter.Value>
       <ControlTemplate TargetType=""{x:Type Separator}"">
         <Border Height=""1""
                 Background=""{StaticResource TrayDivider}""/>
       </ControlTemplate>
     </Setter.Value>
   </Setter>
 </Style>
</ResourceDictionary>";

        var resources =
            (System.Windows.ResourceDictionary)
            System.Windows.Markup.XamlReader.Parse(
                themeXaml);

        menu.Template =
            (System.Windows.Controls.ControlTemplate)
            resources["QuietShieldTrayContextMenuTemplate"];

        menu.Background =
            (System.Windows.Media.Brush)
            resources["TraySurface"];

        menu.Foreground =
            System.Windows.Media.Brushes.White;

        menu.BorderBrush =
            (System.Windows.Media.Brush)
            resources["TrayDivider"];

        menu.BorderThickness =
            new System.Windows.Thickness(1);

        menu.Padding =
            new System.Windows.Thickness(0);

        menu.HasDropShadow = true;

        var itemStyle =
            (System.Windows.Style)
            resources["QuietShieldTrayMenuItemStyle"];

        var separatorStyle =
            (System.Windows.Style)
            resources["QuietShieldTraySeparatorStyle"];

        foreach (var item in menu.Items)
        {
            if (item is MenuItem menuItem)
            {
                menuItem.Style = itemStyle;
            }
            else if (item is Separator separator)
            {
                separator.Style = separatorStyle;
            }
        }
    }
    private IntPtr WindowProcedure(
        IntPtr window,
        int message,
        IntPtr wParam,
        IntPtr lParam,
        ref bool handled)
    {
        if (message != TrayCallbackMessage)
        {
            return IntPtr.Zero;
        }

        var trayMessage = unchecked((int)lParam.ToInt64());

        switch (trayMessage)
        {
            case WmLeftButtonUp:
                _window?.ShowFromTray();
                handled = true;
                break;

            case WmRightButtonUp:
                UpdatePresentation();

                if (_contextMenu is not null)
                {
                    _contextMenu.IsOpen = true;
                }

                handled = true;
                break;
        }

        return IntPtr.Zero;
    }

    private void OnOpenClick(
        object sender,
        System.Windows.RoutedEventArgs args) =>
        _window?.ShowFromTray();

    private void OnProtectionClick(
        object sender,
        System.Windows.RoutedEventArgs args)
    {
        _window?.ShowFromTray();
        _viewModel?.ProtectionToggleCommand.Execute(null);
    }

    private void OnDataSavingClick(
        object sender,
        System.Windows.RoutedEventArgs args) =>
        _viewModel?.UseDataSavingModeCommand.Execute(null);

    private void OnWiFiClick(
        object sender,
        System.Windows.RoutedEventArgs args) =>
        _viewModel?.UseWiFiModeCommand.Execute(null);

    private void OnPrivateBrowserClick(
        object sender,
        System.Windows.RoutedEventArgs args)
    {
        _window?.ShowFromTray();
        _viewModel?.OpenPrivateBrowserPageCommand.Execute(null);
    }

    private void OnFileSafetyClick(
        object sender,
        System.Windows.RoutedEventArgs args)
    {
        _window?.ShowFromTray();
        _viewModel?.OpenFileSafetyPageCommand.Execute(null);
    }

    private void OnActivityClick(
        object sender,
        System.Windows.RoutedEventArgs args)
    {
        _window?.ShowFromTray();
        _viewModel?.OpenActivityPageCommand.Execute(null);
    }

    private void OnExitClick(
        object sender,
        System.Windows.RoutedEventArgs args) =>
        _requestExit?.Invoke();

    private void OnViewModelPropertyChanged(
        object? sender,
        PropertyChangedEventArgs args)
    {
        if (args.PropertyName is
            nameof(MainViewModel.OperatingModeDisplay) or
            nameof(MainViewModel.OperatingMode) or
            nameof(MainViewModel.ConsumerProtectionIsOn) or
            nameof(MainViewModel.ConsumerProtectionStateLabel) or
            nameof(MainViewModel.ConsumerProtectionHeadline))
        {
            UpdatePresentation();
        }
    }

    private void UpdatePresentation()
    {
        if (_viewModel is null)
        {
            return;
        }

        if (_statusItem is not null)
        {
            _statusItem.Header =
                "QuietShield - Protection " +
                (_viewModel.ConsumerProtectionIsOn ? "ON" : "OFF");
        }

        if (_protectionItem is not null)
        {
            _protectionItem.Header =
                _viewModel.ConsumerProtectionIsOn
                    ? "Turn Protection Off"
                    : "Turn Protection On";
        }

        if (_dataSavingItem is not null)
        {
            _dataSavingItem.Header =
                (_viewModel.IsDataSavingModeActive ? "â—  " : "â—‹  ") +
                "Data Saving Mode";
        }

        if (_wiFiItem is not null)
        {
            _wiFiItem.Header =
                (_viewModel.IsWiFiModeActive ? "â—  " : "â—‹  ") +
                "Wi-Fi Mode";
        }

        if (!_iconAdded)
        {
            return;
        }

        _notifyData.ToolTip =
            "QuietShield - " +
            (_viewModel.ConsumerProtectionIsOn ? "Protection On" : "Protection Off") +
            " - " +
            (_viewModel.IsDataSavingModeActive ? "Data Saving" : "Wi-Fi Mode");

        try
        {
            _ = ShellNotifyIcon(NotifyIconModify, ref _notifyData);
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or
            EntryPointNotFoundException or
            ExternalException)
        {
            IntegrationRuntimeDiagnostics.WriteException(
                "Tray",
                "Tray presentation update failed.",
                exception);
        }
    }

    private void TryDeleteNativeIcon()
    {
        try
        {
            _ = ShellNotifyIcon(NotifyIconDelete, ref _notifyData);
        }
        catch
        {
        }
    }

    private void RemoveHook()
    {
        if (_source is null)
        {
            return;
        }

        _source.RemoveHook(WindowProcedure);
        _source = null;
    }

    private void RemoveMenuHandlers()
    {
        if (_openItem is not null) _openItem.Click -= OnOpenClick;
        if (_protectionItem is not null) _protectionItem.Click -= OnProtectionClick;
        if (_dataSavingItem is not null) _dataSavingItem.Click -= OnDataSavingClick;
        if (_wiFiItem is not null) _wiFiItem.Click -= OnWiFiClick;
        if (_privateBrowserItem is not null) _privateBrowserItem.Click -= OnPrivateBrowserClick;
        if (_fileSafetyItem is not null) _fileSafetyItem.Click -= OnFileSafetyClick;
        if (_activityItem is not null) _activityItem.Click -= OnActivityClick;
        if (_exitItem is not null) _exitItem.Click -= OnExitClick;
    }

#pragma warning disable SYSLIB1054
    [DllImport(
        "shell32.dll",
        EntryPoint = "Shell_NotifyIconW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShellNotifyIcon(
        uint message,
        ref NotifyIconData data);

    [DllImport(
        "user32.dll",
        EntryPoint = "LoadImageW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr LoadImage(
        IntPtr instance,
        string name,
        uint type,
        int width,
        int height,
        uint load);

    [DllImport(
        "user32.dll",
        EntryPoint = "DestroyIcon",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr icon);
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
