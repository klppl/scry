@echo off
setlocal
cd /d "%~dp0"
echo ================================================================
echo  Starting SCRY...
echo ================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scry.ps1" %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Scan finished with error code %ERRORLEVEL%.
)
echo.
pause
