@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows\Launch-Demo.ps1" %*
exit /b %ERRORLEVEL%
