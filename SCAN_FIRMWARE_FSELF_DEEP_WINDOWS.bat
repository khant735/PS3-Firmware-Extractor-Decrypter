@echo off
cd /d "%~dp0"
py -3 firmware_fself_scan.py "%~1" --deep
pause
