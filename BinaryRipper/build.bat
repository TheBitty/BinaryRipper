@echo off
:: Look for Visual Studio installations
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not defined VS_PATH (
    echo Visual Studio installation not found.
    exit /b 1
)

:: Set up Visual Studio environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 || (
    echo Failed to set up Visual Studio environment.
    exit /b 1
)

:: Build the project
msbuild "%~dp0BinaryRipper.vcxproj" /p:Configuration=Debug /p:Platform=x64 /m /v:m

if %ERRORLEVEL% NEQ 0 (
    echo Build failed.
    exit /b %ERRORLEVEL%
)

echo Build successful.
exit /b 0 