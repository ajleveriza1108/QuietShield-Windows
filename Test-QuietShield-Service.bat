@echo off
rem Manual exact-service validation entry point. Requires an already elevated console and never self-elevates.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Test-QuietShieldService.ps1" %*
exit /b %ERRORLEVEL%
