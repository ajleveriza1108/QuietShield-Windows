namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private bool _showSystemDataSavingApplications;

    public bool ShowSystemDataSavingApplications
    {
        get => _showSystemDataSavingApplications;
        set
        {
            if (SetField(ref _showSystemDataSavingApplications, value))
            {
                DataSavingApplicationsView.Refresh();
                OnPropertyChanged(nameof(DataSavingSystemVisibilityNotice));
            }
        }
    }

    public string DataSavingSystemVisibilityNotice =>
        ShowSystemDataSavingApplications
            ? "Windows system components are visible for inspection. They remain protected and cannot be restricted by Data Saving."
            : "Windows system components are hidden. Turn this on to inspect protected system entries.";
}
