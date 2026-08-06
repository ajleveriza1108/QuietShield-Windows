using System.Windows;
using System.Windows.Controls;

namespace QuietShield.App.Controls;

public partial class ResponsivePageShell : UserControl
{
    public static readonly DependencyProperty TitleProperty = DependencyProperty.Register(
        nameof(Title), typeof(string), typeof(ResponsivePageShell), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(
        nameof(Description), typeof(string), typeof(ResponsivePageShell), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty StatusTextProperty = DependencyProperty.Register(
        nameof(StatusText), typeof(string), typeof(ResponsivePageShell), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty PrimaryActionsProperty = DependencyProperty.Register(
        nameof(PrimaryActions), typeof(object), typeof(ResponsivePageShell), new PropertyMetadata(null));

    public static readonly DependencyProperty PageContentProperty = DependencyProperty.Register(
        nameof(PageContent), typeof(object), typeof(ResponsivePageShell), new PropertyMetadata(null));

    public ResponsivePageShell() => InitializeComponent();

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    public string Description
    {
        get => (string)GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    public string StatusText
    {
        get => (string)GetValue(StatusTextProperty);
        set => SetValue(StatusTextProperty, value);
    }

    public object? PrimaryActions
    {
        get => GetValue(PrimaryActionsProperty);
        set => SetValue(PrimaryActionsProperty, value);
    }

    public object? PageContent
    {
        get => GetValue(PageContentProperty);
        set => SetValue(PageContentProperty, value);
    }

    public ScrollViewer ScrollViewer => PageScroller;
}
