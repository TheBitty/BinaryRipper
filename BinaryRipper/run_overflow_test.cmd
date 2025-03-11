@echo off
echo ================================================================
echo              BUFFER OVERFLOW CRASH DEMONSTRATION
echo ================================================================
echo This test will deliberately crash the program to demonstrate
echo a buffer overflow vulnerability.
echo.
echo Press any key to begin the test...
pause > nul
echo.
echo Username prompt will appear. Enter the following:
echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
echo.
echo Then password prompt will appear. Enter the following:
echo BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
echo.
echo Starting test program now...
echo ================================================================
"testcases\BasicOverflowTest_Crash.exe"
echo.
echo ================================================================
if %ERRORLEVEL% NEQ 0 (
    echo TEST RESULT: CRASH DETECTED! (Exit code: %ERRORLEVEL%)
    echo This confirms the buffer overflow vulnerability.
) else (
    echo TEST RESULT: Program exited normally.
    echo No crash was detected. Try with longer input.
)
echo ================================================================
echo Press any key to close this window...
pause > nul
