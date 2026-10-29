@echo off
cd /d "%~dp0frontend"
start "" http://localhost:8080
python -m http.server 8080
pause
