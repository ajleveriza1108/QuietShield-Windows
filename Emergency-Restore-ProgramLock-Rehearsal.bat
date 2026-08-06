@echo off
rem Manual exact-rule rollback entry point. Requires an already elevated console and never self-elevates.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Restore-ProgramLockRehearsal.ps1" %*
exit /b %ERRORLEVEL%
