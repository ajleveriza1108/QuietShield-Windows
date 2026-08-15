@echo off
setlocal EnableExtensions

set "REPO=D:\Windows Projects\QuietShield-Windows"
set "PROJECT=%REPO%\src\QuietShield.App\QuietShield.App.csproj"
set "APP=%REPO%\artifacts\bin\QuietShield.App\x64\Release\net10.0-windows\QuietShield.App.exe"
set "DLL=%REPO%\artifacts\bin\QuietShield.App\x64\Release\net10.0-windows\QuietShield.App.dll"

cd /d "%REPO%"
title QuietShield Windows - Development Launcher

echo QuietShield Windows
echo Building current Release x64 GUI...
echo.

dotnet.exe build "%PROJECT%" -c Release -p:Platform=x64 --nologo
if errorlevel 1 (
    echo.
    echo [FAILED] QuietShield build failed. The app was not launched.
    pause
    exit /b 1
)

if not exist "%APP%" (
    echo [FAILED] Expected app was not produced:
    echo %APP%
    pause
    exit /b 2
)

if not exist "%DLL%" (
    echo [FAILED] Expected WPF DLL was not produced:
    echo %DLL%
    pause
    exit /b 3
)

echo [PASS] Launching current x64 development build...
start "" /D "%REPO%\artifacts\bin\QuietShield.App\x64\Release\net10.0-windows" "%APP%"

exit /b 0
