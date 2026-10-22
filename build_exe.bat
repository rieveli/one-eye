@echo off
REM Builds dist\OneEye\OneEye.exe with PyInstaller.
REM Run from this folder:  build_exe.bat
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo Virtual env missing. Run: py -3.13 -m venv .venv ^&^& .venv\Scripts\python -m pip install -r requirements.txt
  exit /b 1
)
.venv\Scripts\python.exe -m pip install -q pyinstaller==6.22.3
.venv\Scripts\python.exe -m PyInstaller ^
  --noconfirm --clean --windowed ^
  --name OneEye ^
  --icon assets\icon.ico ^
  --add-data "rules;rules" ^
  --add-data "assets;assets" ^
  --collect-submodules sklearn ^
  --exclude-module tkinter ^
  --exclude-module PySide6.QtWebEngineCore ^
  --exclude-module PySide6.QtWebEngineWidgets ^
  --exclude-module PySide6.Qt3DCore ^
  main.py
echo.
echo Done: dist\OneEye\OneEye.exe
echo Tip: test the .exe on the demo laptop. Unsigned PyInstaller builds are sometimes
echo      falsely flagged by Windows Defender / SmartScreen.
