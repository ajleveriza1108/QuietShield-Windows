@echo off
setlocal
rem Manual emergency entry point only. This launcher is never called automatically.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Restore-OriginalDns.ps1" %*
exit /b %errorlevel%
