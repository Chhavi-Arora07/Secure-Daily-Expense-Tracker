@echo off
rem Compiles the project into the "out" folder. Needs JDK 17+ and the two jars in lib\ (see README).
cd /d "%~dp0"
if not exist lib\*.jar (
  echo Put sqlite-jdbc-*.jar and slf4j-api-*.jar into the lib folder first. See lib\README.txt
  exit /b 1
)
if exist out rmdir /s /q out
mkdir out
dir /s /b src\main\java\*.java > sources-main.txt
dir /s /b src\test\java\*.java > sources-test.txt
javac --release 17 -cp "lib\*" -d out @sources-main.txt || exit /b 1
xcopy /E /I /Y src\main\resources out >nul
javac --release 17 -cp "out;lib\*" -d out @sources-test.txt || exit /b 1
del sources-main.txt sources-test.txt
echo Build OK.
echo Run the app:     run.bat
echo Run the checks:  run.bat check
