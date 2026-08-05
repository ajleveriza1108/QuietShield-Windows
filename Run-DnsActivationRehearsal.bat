@echo off
setlocal
rem Manual explicit rehearsal entry point. This launcher never requests elevation.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Invoke-DnsActivationRehearsal.ps1" %*
exit /b %errorlevel%
