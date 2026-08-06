@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Test-ServiceCommunication.ps1"
exit /b %ERRORLEVEL%
