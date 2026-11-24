@echo off
rem run.bat         starts the application
rem run.bat check   runs the security verification checks
cd /d "%~dp0"
if /i "%1"=="check" (
  java -cp "out;lib/*" expensetracker.SecurityCheck
) else (
  java -cp "out;lib/*" expensetracker.Main
)
