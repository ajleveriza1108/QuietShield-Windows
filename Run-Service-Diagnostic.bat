@echo off
setlocal
set "ROOT=%~dp0"
set "SERVICE=%ROOT%artifacts\bin\QuietShield.Service\Debug\net10.0-windows\QuietShield.Service.exe"
if not exist "%SERVICE%" (
  echo QuietShield.Service Debug build was not found. Run the approved validation build first.
  exit /b 2
)
"%SERVICE%" --diagnostic --state-root "%ROOT%artifacts\phase10a\diagnostic-state"
exit /b %ERRORLEVEL%
