@echo off
cd /d "%~dp0"
set /p "FOLDER=Existing firmware output folder: "
py -3 spkg_overlay_audit.py "%FOLDER%"
pause
