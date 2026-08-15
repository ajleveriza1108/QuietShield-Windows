@echo off
setlocal EnableExtensions
title QuietShield Windows - Live Dev Mode 0.12.0-beta.1

set "APP=C:\Program Files\QuietShield\App\0.12.0-beta.1\QuietShield.App.exe"

if not exist "%APP%" (
  echo [STOP] QuietShield Live Dev app is not installed.
  echo Run RUN-QUIETSHIELD-LIVE-DEV-MODE-AS-ADMIN.bat and choose Enable.
  pause
  exit /b 2
)

echo Launching QuietShield Live Dev Mode...
echo Real Program Connection Lock is available only while QuietShieldService is running.
echo DNS activation remains disabled.
echo.
start "" "%APP%"
exit /b 0