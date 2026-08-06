using QuietShield.Core.Presentation;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class ResponsiveLayoutTests
{
    [TestMethod]
    public void NavigationAutomaticallyCompactsAtNarrowWidths()
    {
        Assert.AreEqual(NavigationDisplayMode.Compact, ResponsiveLayout.GetNavigationMode(1024d, false));
        Assert.AreEqual(NavigationDisplayMode.Expanded, ResponsiveLayout.GetNavigationMode(1366d, false));
        Assert.AreEqual(NavigationDisplayMode.Compact, ResponsiveLayout.GetNavigationMode(1920d, true));
    }

    [TestMethod]
    public void AdaptiveCardsAndFormsCollapseWithoutHorizontalOverflow()
    {
        Assert.AreEqual(1, ResponsiveLayout.CalculateAdaptiveColumnCount(470d, 300d, 14d, 2));
        Assert.AreEqual(2, ResponsiveLayout.CalculateAdaptiveColumnCount(900d, 300d, 14d, 2));
        Assert.AreEqual(3, ResponsiveLayout.CalculateAdaptiveColumnCount(1100d, 240d, 14d, 3));
    }

    [TestMethod]
    public void SavedOffScreenWindowMovesIntoNearestWorkArea()
    {
        var monitors = new[]
        {
            new UiRect(0d, 0d, 1920d, 1040d),
            new UiRect(1920d, 0d, 2560d, 1400d)
        };
        var result = ResponsiveLayout.ConstrainWindowPlacement(
            new SavedWindowPlacement(9000d, -4000d, 1180d, 760d, true),
            monitors,
            new UiSize(960d, 600d));

        Assert.AreEqual(new SavedWindowPlacement(3300d, 0d, 1180d, 760d, true), result);
    }

    [TestMethod]
    public void OversizedSavedWindowIsClampedToWorkArea()
    {
        var workArea = new UiRect(0d, 0d, 1024d, 640d);
        var result = ResponsiveLayout.ConstrainWindowPlacement(
            new SavedWindowPlacement(-200d, -100d, 4000d, 3000d, false),
            new[] { workArea },
            new UiSize(960d, 600d));

        Assert.AreEqual(workArea, new UiRect(result.Left, result.Top, result.Width, result.Height));
    }

    [TestMethod]
    public void DialogSizeNeverExceedsCurrentWorkArea()
    {
        var result = ResponsiveLayout.ConstrainDialogSize(
            new UiSize(2400d, 1800d),
            new UiRect(0d, 0d, 1024d, 640d));

        Assert.AreEqual(921.6d, result.Width, 0.01d);
        Assert.AreEqual(576d, result.Height, 0.01d);
    }

    [TestMethod]
    [DataRow(100)]
    [DataRow(125)]
    [DataRow(150)]
    [DataRow(200)]
    public void DpiScenariosProduceFiniteDeviceIndependentViewports(int scalingPercent)
    {
        var effective = ResponsiveLayout.GetEffectiveViewport(2048d, 1280d, scalingPercent);

        Assert.IsTrue(double.IsFinite(effective.Width) && effective.Width > 0d);
        Assert.IsTrue(double.IsFinite(effective.Height) && effective.Height > 0d);
    }
}
