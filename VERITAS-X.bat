@echo off
title VERITAS-X Digital Forensics Platform
cls
echo ==============================================================
echo   VERITAS-X : Digital Forensics ^& Evidence Verification
echo   Trust the evidence. Verify the conclusion.
echo ==============================================================
echo.
echo Starting VERITAS-X local-first forensics platform...
set "PYTHONPATH=%~dp0"
set "PATH=%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%PATH%"

"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" "%~dp0launcher.py"
pause
