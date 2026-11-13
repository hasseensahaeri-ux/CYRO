@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (py -3 -m venv .venv)
call .venv\Scripts\activate
python -m pip install -r requirements.txt -q
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:5000"
python app.py
pause
