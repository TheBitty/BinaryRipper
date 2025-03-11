@echo off
echo Building BinaryRipper...
call build.bat

if %ERRORLEVEL% NEQ 0 (
    echo Build failed.
    pause
    exit /b %ERRORLEVEL%
)

echo Running BinaryRipper...
"%~dp0x64\Debug\BinaryRipper.exe"

pause 