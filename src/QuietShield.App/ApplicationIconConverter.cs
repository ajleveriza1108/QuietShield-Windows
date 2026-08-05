using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Data;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using QuietShield.Windows.Integration;

namespace QuietShield.App;

public sealed class ApplicationIconConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => LoadIcon(value as ApplicationIconReference);

    public static BitmapSource? LoadIcon(ApplicationIconReference? iconReference)
    {
        if (iconReference is null || !File.Exists(iconReference.SourcePath)) return null;
        try
        {
            using var icon = Icon.ExtractAssociatedIcon(iconReference.SourcePath);
            if (icon is null) return null;
            var image = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, System.Windows.Int32Rect.Empty, BitmapSizeOptions.FromWidthAndHeight(32, 32));
            image.Freeze();
            return image;
        }
        catch (ArgumentException) { return null; }
        catch (ExternalException) { return null; }
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
