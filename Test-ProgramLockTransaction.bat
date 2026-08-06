@echo off
rem Read-only Phase 8 transaction simulation. Never elevates.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Test-ProgramLockTransaction.ps1" %*
exit /b %ERRORLEVEL%
