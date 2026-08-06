namespace QuietShield.App.ViewModels;

public sealed record NavigationItem(
    string Title,
    string Description,
    string Glyph,
    string Status,
    bool IsDashboard = false);
