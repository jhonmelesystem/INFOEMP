@echo off
timeout /t 15 /nobreak > nul
start /min cmd /c "cloudflared tunnel --url http://localhost:5000"