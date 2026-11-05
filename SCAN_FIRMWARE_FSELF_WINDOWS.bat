@echo off
setlocal
cd /d "%~dp0"
set /p "ROOT=Enter extracted firmware output folder: "
py -3 firmware_fself_scan.py "%ROOT%"
pause
