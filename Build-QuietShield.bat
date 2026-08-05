@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Build-QuietShield.ps1" %*
exit /b %ERRORLEVEL%
