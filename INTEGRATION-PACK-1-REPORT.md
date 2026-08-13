# QuietShield Windows â€” Integration Pack 1

Status: **Local test milestone**

Branch:

`feature/integration-pack-1-data-modes-tray`

## Included

- Data Saving and Wi-Fi primary operating modes
- persistent local profile state under `%LocalAppData%\QuietShield\Modes`
- per-user-application Data Saving allow selection
- Windows system-component safety treatment: red `SYSTEM â€¢ PROTECTED`, non-toggleable
- lightweight Windows tray icon with no polling timer
- left-click tray icon to restore the GUI
- right-click tray menu for Data Saving, Wi-Fi Mode, Open, and Exit
- close-to-tray lifecycle for normal application runs
- smoke/test runs do not create a tray icon
- Dashboard operating-mode shortcut
- dedicated Data Saving & Wi-Fi page
- deterministic Data Saving policy planner and Core tests

## Low-resource design

- no WebView2/Chromium runtime is created by Integration Pack 1
- no continuous tray animation
- no tray polling timer
- GUI is hidden when closed to tray rather than continuously redrawn
- existing event-driven Windows network refresh behavior is preserved

## Safety boundary

Integration Pack 1 intentionally does **not** batch-create or remove Windows Firewall rules. The selected mode, profile, network classification, tray behavior, and per-app Data Saving plan are live local state. Machine enforcement is reserved for a separately gated step after UI/runtime testing.

Windows adapter/system DNS activation remains safety-gated.

No installer, startup registration, service mutation, Firewall mutation, DNS mutation, WFP mutation, adapter mutation, Git commit, or Git push is performed by this update.
