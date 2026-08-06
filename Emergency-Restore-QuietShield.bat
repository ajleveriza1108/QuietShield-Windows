@echo off
rem Manual exact-transaction restore entry point. Requires an already elevated console and never self-elevates.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Restore-QuietShieldServiceState.ps1" %*
exit /b %ERRORLEVEL%
