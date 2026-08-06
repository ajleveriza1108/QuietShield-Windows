@echo off
rem Manual Phase 9 entry point. Requires an already elevated console and never self-elevates.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Invoke-ProgramLockFirewallRehearsal.ps1" %*
exit /b %ERRORLEVEL%
