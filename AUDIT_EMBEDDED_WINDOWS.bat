@echo off
cd /d "%~dp0"
set /p TARGET=Enter full path to ELF/SELF file: 
py -3 embedded_container_audit.py "%TARGET%"
pause
