@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Show-DnsTransactionState.ps1" %*
exit /b %errorlevel%
