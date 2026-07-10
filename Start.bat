@echo off

REM Pokreni Python aplikaciju u novom prozoru
start cmd /k "python app.py"

REM Sačekaj nekoliko sekundi da se server podigne
timeout /t 5 /nobreak >nul

REM Otvori browser
start http://localhost:5000