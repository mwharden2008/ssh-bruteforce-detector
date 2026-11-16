@echo off
setlocal
cd /d "%~dp0"
echo.
echo SSH Auth Log Analyzer ^& Brute-Force Detector
echo -------------------------------------------
where py >nul 2>&1
if not errorlevel 1 (
    py -3 src\parser.py --year 2026
    goto result
)
where python >nul 2>&1
if not errorlevel 1 (
    python src\parser.py --year 2026
    goto result
)
echo Python not found. Install Python 3.9 or newer from python.org.
:result
echo.
echo To run automated tests, use: py -3 -m unittest discover -s tests -v
echo.
pause
endlocal
