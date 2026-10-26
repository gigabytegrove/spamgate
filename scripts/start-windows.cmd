@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"
title SpamGate - Local Console

echo.
echo  SpamGate - Portable Windows
echo  ---------------------------------------
echo  URL: http://127.0.0.1:38470/
echo  Data: %LOCALAPPDATA%\SpamGate
echo  No administrator privileges required.
echo  Keep this window open while using SpamGate.
echo  The first-run claim key is displayed below.
echo.

if not exist "%~dp0spamgate.exe" (
  echo  ERROR: spamgate.exe is missing from this directory.
  goto :failed
)
if "%LOCALAPPDATA%"=="" (
  echo  ERROR: LOCALAPPDATA is not set for this Windows account.
  goto :failed
)

"%~dp0spamgate.exe" -data "%LOCALAPPDATA%\SpamGate" -listen "127.0.0.1:38470"
set "SPAMGATE_EXIT=%ERRORLEVEL%"
echo.
echo  SpamGate stopped with exit code %SPAMGATE_EXIT%.
if not "%SPAMGATE_EXIT%"=="0" (
  echo  Check the error message above. Another service may already use port 38470.
)
:failed
echo.
echo  Press any key to close this window.
pause >nul
endlocal
