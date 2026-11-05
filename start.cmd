@echo off
setlocal
chcp 65001 >nul
pushd "%~dp0" || exit /b 1
if exist "%LocalAppData%\Programs\Python\Python313\python.exe" goto local
py -3 -c "import sys,tkinter;sys.exit(sys.version_info < (3,10))" >nul 2>&1
if not errorlevel 1 goto launcher
python -c "import sys,tkinter;sys.exit(sys.version_info < (3,10))" >nul 2>&1
if errorlevel 1 goto missing
python -B gui.py
goto done
:local
"%LocalAppData%\Programs\Python\Python313\python.exe" -B gui.py
goto done
:launcher
py -3 -B gui.py
goto done
:missing
echo Install Python 3.10 or newer with Tcl/Tk, extract the entire app ZIP, and start again.
pause
exit /b 1
:done
if errorlevel 1 pause
popd
