@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Test-DnsTransactionPlan.ps1" %*
exit /b %errorlevel%
