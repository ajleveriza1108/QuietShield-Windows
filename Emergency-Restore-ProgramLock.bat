@echo off
rem Manual future emergency entry point only. Never elevates; Phase 8 cannot modify Windows.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Restore-ProgramLockRules.ps1" %*
exit /b %ERRORLEVEL%
