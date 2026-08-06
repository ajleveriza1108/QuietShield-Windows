@echo off
rem Read-only Phase 9 rehearsal state viewer. Never elevates.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Show-ProgramLockRehearsalState.ps1" %*
exit /b %ERRORLEVEL%
