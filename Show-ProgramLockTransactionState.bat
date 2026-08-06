@echo off
rem Read-only Phase 8 state viewer. Never elevates.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Show-ProgramLockTransactionState.ps1" %*
exit /b %ERRORLEVEL%
