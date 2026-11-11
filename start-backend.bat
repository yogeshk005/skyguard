@echo off
cd /d "%~dp0backend"
py -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
if not exist .env copy .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
