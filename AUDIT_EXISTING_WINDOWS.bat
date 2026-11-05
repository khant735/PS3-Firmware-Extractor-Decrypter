@echo off
setlocal
cd /d "%~dp0"
echo Select the EXISTING extraction output folder, for example output\update_files
set /p "FOLDER=Extraction folder path: "
py -3 audit_existing_extraction.py "%FOLDER%"
if errorlevel 1 python audit_existing_extraction.py "%FOLDER%"
pause
