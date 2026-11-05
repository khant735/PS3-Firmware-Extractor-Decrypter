@echo off
setlocal
if "%~1"=="" (echo Drag an extracted firmware folder onto this BAT file. & pause & exit /b 1)
py -3 "%~dp0firmware_format_scan.py" "%~1"
pause
