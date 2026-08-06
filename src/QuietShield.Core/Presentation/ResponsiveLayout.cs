namespace QuietShield.Core.Presentation;

public readonly record struct UiRect(double Left, double Top, double Width, double Height)
{
    public double Right => Left + Width;
    public double Bottom => Top + Height;
    public double CenterX => Left + (Width / 2d);
    public double CenterY => Top + (Height / 2d);
}

public readonly record struct UiSize(double Width, double Height);

public readonly record struct SavedWindowPlacement(
    double Left,
    double Top,
    double Width,
    double Height,
    bool IsMaximized);

public enum NavigationDisplayMode
{
    Expanded,
    Compact
}

public static class ResponsiveLayout
{
    public const double CompactNavigationBreakpoint = 1120d;
    public const double ExpandedNavigationWidth = 252d;
    public const double CompactNavigationWidth = 68d;
    public const double WidePagePadding = 24d;
    public const double CompactPagePadding = 16d;

    public static NavigationDisplayMode GetNavigationMode(double viewportWidth, bool userRequestedCompact) =>
        userRequestedCompact || viewportWidth < CompactNavigationBreakpoint
            ? NavigationDisplayMode.Compact
            : NavigationDisplayMode.Expanded;

    public static double GetNavigationWidth(NavigationDisplayMode mode) =>
        mode == NavigationDisplayMode.Compact ? CompactNavigationWidth : ExpandedNavigationWidth;

    public static double GetPagePadding(double viewportWidth) =>
        viewportWidth < CompactNavigationBreakpoint ? CompactPagePadding : WidePagePadding;

    public static int CalculateAdaptiveColumnCount(double availableWidth, double minimumItemWidth, double spacing, int maximumColumns)
    {
        if (!double.IsFinite(availableWidth) || availableWidth <= 0d ||
            !double.IsFinite(minimumItemWidth) || minimumItemWidth <= 0d ||
            !double.IsFinite(spacing) || spacing < 0d || maximumColumns < 1)
        {
            return 1;
        }

        var columns = (int)Math.Floor((availableWidth + spacing) / (minimumItemWidth + spacing));
        return Math.Clamp(columns, 1, maximumColumns);
    }

    public static UiSize GetEffectiveViewport(double physicalWidth, double physicalHeight, int scalingPercent)
    {
        if (!double.IsFinite(physicalWidth) || physicalWidth <= 0d ||
            !double.IsFinite(physicalHeight) || physicalHeight <= 0d ||
            scalingPercent is < 100 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(scalingPercent), "The physical dimensions and scaling percentage must be positive and bounded.");
        }

        var scale = scalingPercent / 100d;
        return new UiSize(physicalWidth / scale, physicalHeight / scale);
    }

    public static SavedWindowPlacement ConstrainWindowPlacement(
        SavedWindowPlacement saved,
        IReadOnlyList<UiRect> workAreas,
        UiSize minimumSize)
    {
        ArgumentNullException.ThrowIfNull(workAreas);
        if (workAreas.Count == 0)
        {
            throw new ArgumentException("At least one monitor work area is required.", nameof(workAreas));
        }

        var validAreas = workAreas.Where(IsUsableRectangle).ToArray();
        if (validAreas.Length == 0)
        {
            throw new ArgumentException("At least one usable monitor work area is required.", nameof(workAreas));
        }

        var fallback = validAreas[0];
        var savedRectangle = IsUsableRectangle(new UiRect(saved.Left, saved.Top, saved.Width, saved.Height))
            ? new UiRect(saved.Left, saved.Top, saved.Width, saved.Height)
            : new UiRect(fallback.Left, fallback.Top, Math.Max(minimumSize.Width, fallback.Width * 0.75d), Math.Max(minimumSize.Height, fallback.Height * 0.75d));
        var target = SelectBestWorkArea(savedRectangle, validAreas);
        var minimumWidth = Math.Min(Math.Max(1d, minimumSize.Width), target.Width);
        var minimumHeight = Math.Min(Math.Max(1d, minimumSize.Height), target.Height);
        var width = Math.Clamp(savedRectangle.Width, minimumWidth, target.Width);
        var height = Math.Clamp(savedRectangle.Height, minimumHeight, target.Height);
        var left = Math.Clamp(savedRectangle.Left, target.Left, target.Right - width);
        var top = Math.Clamp(savedRectangle.Top, target.Top, target.Bottom - height);

        return new SavedWindowPlacement(left, top, width, height, saved.IsMaximized);
    }

    public static UiSize ConstrainDialogSize(UiSize requested, UiRect workArea, double maximumWorkAreaRatio = 0.9d)
    {
        if (!IsUsableRectangle(workArea) || maximumWorkAreaRatio is <= 0d or > 1d)
        {
            throw new ArgumentOutOfRangeException(nameof(workArea), "A usable work area and ratio are required.");
        }

        var width = double.IsFinite(requested.Width) && requested.Width > 0d ? requested.Width : workArea.Width * 0.6d;
        var height = double.IsFinite(requested.Height) && requested.Height > 0d ? requested.Height : workArea.Height * 0.6d;
        return new UiSize(
            Math.Min(width, workArea.Width * maximumWorkAreaRatio),
            Math.Min(height, workArea.Height * maximumWorkAreaRatio));
    }

    private static UiRect SelectBestWorkArea(UiRect saved, IReadOnlyList<UiRect> workAreas)
    {
        var intersecting = workAreas
            .Select(area => new { Area = area, Intersection = IntersectionArea(saved, area) })
            .OrderByDescending(static candidate => candidate.Intersection)
            .First();
        if (intersecting.Intersection > 0d)
        {
            return intersecting.Area;
        }

        return workAreas
            .OrderBy(area => DistanceSquared(saved.CenterX, saved.CenterY, area.CenterX, area.CenterY))
            .First();
    }

    private static double IntersectionArea(UiRect first, UiRect second)
    {
        var width = Math.Max(0d, Math.Min(first.Right, second.Right) - Math.Max(first.Left, second.Left));
        var height = Math.Max(0d, Math.Min(first.Bottom, second.Bottom) - Math.Max(first.Top, second.Top));
        return width * height;
    }

    private static double DistanceSquared(double x1, double y1, double x2, double y2)
    {
        var x = x1 - x2;
        var y = y1 - y2;
        return (x * x) + (y * y);
    }

    private static bool IsUsableRectangle(UiRect rectangle) =>
        double.IsFinite(rectangle.Left) && double.IsFinite(rectangle.Top) &&
        double.IsFinite(rectangle.Width) && double.IsFinite(rectangle.Height) &&
        rectangle.Width > 0d && rectangle.Height > 0d;
}
