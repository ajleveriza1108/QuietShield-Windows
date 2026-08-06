using System.Windows;
using System.Windows.Controls;
using QuietShield.Core.Presentation;

namespace QuietShield.App.Controls;

public sealed class AdaptiveGridPanel : Panel
{
    public static readonly DependencyProperty ItemMinWidthProperty = DependencyProperty.Register(
        nameof(ItemMinWidth), typeof(double), typeof(AdaptiveGridPanel),
        new FrameworkPropertyMetadata(280d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty SpacingProperty = DependencyProperty.Register(
        nameof(Spacing), typeof(double), typeof(AdaptiveGridPanel),
        new FrameworkPropertyMetadata(14d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty MaximumColumnsProperty = DependencyProperty.Register(
        nameof(MaximumColumns), typeof(int), typeof(AdaptiveGridPanel),
        new FrameworkPropertyMetadata(3, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public double ItemMinWidth
    {
        get => (double)GetValue(ItemMinWidthProperty);
        set => SetValue(ItemMinWidthProperty, value);
    }

    public double Spacing
    {
        get => (double)GetValue(SpacingProperty);
        set => SetValue(SpacingProperty, value);
    }

    public int MaximumColumns
    {
        get => (int)GetValue(MaximumColumnsProperty);
        set => SetValue(MaximumColumnsProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var width = double.IsInfinity(availableSize.Width) ? ItemMinWidth : Math.Max(0d, availableSize.Width);
        var columns = ResponsiveLayout.CalculateAdaptiveColumnCount(width, ItemMinWidth, Spacing, MaximumColumns);
        var cellWidth = Math.Max(0d, (width - (Spacing * (columns - 1))) / columns);
        var rowHeights = new List<double>();

        for (var index = 0; index < InternalChildren.Count; index++)
        {
            var child = InternalChildren[index];
            child.Measure(new Size(cellWidth, double.PositiveInfinity));
            var row = index / columns;
            if (row == rowHeights.Count)
            {
                rowHeights.Add(child.DesiredSize.Height);
            }
            else
            {
                rowHeights[row] = Math.Max(rowHeights[row], child.DesiredSize.Height);
            }
        }

        var height = rowHeights.Sum() + (Spacing * Math.Max(0, rowHeights.Count - 1));
        return new Size(width, height);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var columns = ResponsiveLayout.CalculateAdaptiveColumnCount(finalSize.Width, ItemMinWidth, Spacing, MaximumColumns);
        var cellWidth = Math.Max(0d, (finalSize.Width - (Spacing * (columns - 1))) / columns);
        var rowHeights = new List<double>();
        for (var index = 0; index < InternalChildren.Count; index++)
        {
            var row = index / columns;
            if (row == rowHeights.Count)
            {
                rowHeights.Add(InternalChildren[index].DesiredSize.Height);
            }
            else
            {
                rowHeights[row] = Math.Max(rowHeights[row], InternalChildren[index].DesiredSize.Height);
            }
        }

        var y = 0d;
        for (var index = 0; index < InternalChildren.Count; index++)
        {
            var row = index / columns;
            var column = index % columns;
            if (column == 0 && row > 0)
            {
                y += rowHeights[row - 1] + Spacing;
            }

            var x = column * (cellWidth + Spacing);
            InternalChildren[index].Arrange(new Rect(x, y, cellWidth, rowHeights[row]));
        }

        return finalSize;
    }
}
