@echo off
cd /d "%~dp0"
set /p ROOT=Enter extracted firmware folder: 
py -3 firmware_mself_scan.py "%ROOT%"
pause
