#include <iostream>
#include <string>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include "includes/BufferOverFlowDetector.h"

#define _CRT_SECURE_NO_WARNINGS

// Forward declaration for the explicit crash test
void runExplicitCrashTest();

// External function declarations from MemoryHooks.cpp
extern "C" {
    bool SetupAllHooks(bool verbose);
    bool SetupMemoryHooks(bool verbose);
    bool SetupStringHooks(bool verbose);
    bool SetupMemoryOperationHooks(bool verbose);
    void SetHookLogFile(const char* logFilePath);
    void RemoveAllHooks();
}

// Print program banner
void printBanner() {
    std::cout << "==============================================" << std::endl;
    std::cout << "      BinaryRipper - Buffer Overflow Detector" << std::endl;
    std::cout << "==============================================" << std::endl;
    std::cout << "A Windows-based binary analysis tool for detecting" << std::endl;
    std::cout << "buffer overflow vulnerabilities." << std::endl;
    std::cout << "==============================================" << std::endl;
}

// Print main menu
void printMenu() {
    std::cout << "\nSelect a test case to run:" << std::endl;
    std::cout << "  1. Basic Buffer Overflow Test" << std::endl;
    std::cout << "  2. Edge Case Tests (off-by-one errors)" << std::endl;
    std::cout << "  3. False Positive Tests" << std::endl;
    std::cout << "  4. Performance Tests (large buffers)" << std::endl;
    std::cout << "  5. Custom Test (specify executable)" << std::endl;
    std::cout << "  6. Explicit Crash Test" << std::endl;
    std::cout << "  7. Exit" << std::endl;
    std::cout << "\nEnter your choice (1-7): ";
}

// Compile test case as a standalone executable
bool compileTestCase(const std::string& sourceFile, const std::string& outputFile, bool disableSecurity = false) {
    // Check if Visual Studio environment is available
    std::string vsPath = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community";

    // Create compilation command, optionally disable security features
    std::string securityFlags = disableSecurity ? "/GS- " : "";
    std::string command = "\"" + std::string(vsPath) + "\\VC\\Auxiliary\\Build\\vcvars64.bat\" && cl.exe /EHsc /DSTANDALONE_TEST " +
        securityFlags + sourceFile + " /Fe:" + outputFile;

    std::cout << "Compiling " << sourceFile << (disableSecurity ? " with security checks disabled" : "") << "..." << std::endl;
    int result = system(command.c_str());

    return (result == 0);
}

// Implementation of test functions

void runBasicOverflowTest() {
    std::cout << "\nRunning Basic Buffer Overflow Test..." << std::endl;

    // Compile test case if not already compiled
    std::string exePath = "testcases\\BasicOverflowTest.exe";
    std::string srcPath = "testcases\\BasicOverflowTest.cpp";

    // Check if the executable exists, if not, compile it
    if (!std::filesystem::exists(exePath)) {
        if (!compileTestCase(srcPath, exePath)) {
            std::cout << "Failed to compile test case. Check compilation errors." << std::endl;
            return;
        }
    }

    // Setup hooks for testing
    std::cout << "Setting up memory function hooks..." << std::endl;
    if (!SetupAllHooks(true)) {
        std::cout << "Failed to set up hooks. Test may not be fully effective." << std::endl;
    }

    SetHookLogFile("basic_overflow_test.log");

    // Create detector instance
    BufferOverflowDetector detector;
    detector.m_executablePath = exePath;
    detector.m_maxStringLength = 100;  // Test with strings up to 100 chars
    detector.m_increment = 5;          // Increase by 5 chars each test
    detector.m_timeout = 10;           // 10 second timeout
    detector.m_verbose = true;         // Detailed output
    detector.m_outputFile = "basic_overflow_results.json";

    // Run the test
    std::cout << "\nRunning tests with different input sizes..." << std::endl;
    bool result = detector.testExecutable();

    if (result) {
        std::cout << "\nBuffer overflow vulnerabilities detected!" << std::endl;
        detector.saveResults();
        std::cout << "Results saved to: " << detector.m_outputFile << std::endl;
    }
    else {
        std::cout << "\nNo buffer overflow vulnerabilities detected." << std::endl;
    }

    // Clean up hooks
    RemoveAllHooks();
}

void runEdgeCaseTest() {
    std::cout << "\nRunning Edge Case Tests..." << std::endl;

    // Similar implementation as BasicOverflowTest but with different parameters
    // and test cases focused on edge conditions like off-by-one errors

    std::cout << "This test focuses on detecting off-by-one errors and boundary conditions." << std::endl;

    // For now, we'll use a stub implementation
    std::cout << "Edge case testing implementation in progress." << std::endl;
}

void runFalsePositiveTest() {
    std::cout << "\nRunning False Positive Tests..." << std::endl;

    // Implementation would test scenarios that might trigger false positives
    // to ensure the detector is accurate

    std::cout << "This test ensures the detector doesn't report false positives." << std::endl;

    // For now, we'll use a stub implementation
    std::cout << "False positive testing implementation in progress." << std::endl;
}

void runPerformanceTest() {
    std::cout << "\nRunning Performance Tests..." << std::endl;

    // Implementation would test the detector with large inputs and
    // measure performance characteristics

    std::cout << "This test evaluates the detector's performance with large buffers." << std::endl;

    // For now, we'll use a stub implementation
    std::cout << "Performance testing implementation in progress." << std::endl;
}

void runCustomTest() {
    std::cout << "\nRunning Custom Test..." << std::endl;

    // Get executable path from user
    std::string exePath;
    std::cout << "Enter the full path to the executable you want to test: ";
    std::cin.ignore();
    std::getline(std::cin, exePath);

    if (!std::filesystem::exists(exePath)) {
        std::cout << "File not found: " << exePath << std::endl;
        return;
    }

    // Setup hooks for testing
    std::cout << "Setting up memory function hooks..." << std::endl;
    if (!SetupAllHooks(true)) {
        std::cout << "Failed to set up hooks. Test may not be fully effective." << std::endl;
    }

    SetHookLogFile("custom_test.log");

    // Configure test parameters
    BufferOverflowDetector detector;
    detector.m_executablePath = exePath;

    // Get test parameters from user
    std::cout << "Enter maximum string length to test: ";
    std::cin >> detector.m_maxStringLength;

    std::cout << "Enter increment size: ";
    std::cin >> detector.m_increment;

    std::cout << "Enter timeout in seconds: ";
    std::cin >> detector.m_timeout;

    detector.m_verbose = true;
    detector.m_outputFile = "custom_test_results.json";

    // Run the test
    std::cout << "\nRunning tests with different input sizes..." << std::endl;
    bool result = detector.testExecutable();

    if (result) {
        std::cout << "\nBuffer overflow vulnerabilities detected!" << std::endl;
        detector.saveResults();
        std::cout << "Results saved to: " << detector.m_outputFile << std::endl;
    }
    else {
        std::cout << "\nNo buffer overflow vulnerabilities detected." << std::endl;
    }

    // Clean up hooks
    RemoveAllHooks();
}

void runExplicitCrashTest() {
    std::cout << "\nRunning Explicit Crash Test..." << std::endl;

    // Compile test case with security checks disabled
    std::string exePath = "testcases\\BasicOverflowTest_Crash.exe";
    std::string srcPath = "testcases\\BasicOverflowTest.cpp";

    // Always recompile with security disabled for the crash test
    if (!compileTestCase(srcPath, exePath, true)) {
        std::cout << "Failed to compile test case. Check compilation errors." << std::endl;
        return;
    }

    // Setup hooks for testing
    std::cout << "Setting up memory function hooks..." << std::endl;
    if (!SetupAllHooks(true)) {
        std::cout << "Failed to set up hooks. Test may not be fully effective." << std::endl;
    }

    SetHookLogFile("explicit_crash_test.log");

    // Set up the visible test window using our detector class
    std::cout << "\nPreparing interactive overflow demonstration..." << std::endl;

    // Create input files with overflow data
    std::ofstream cmdFile("run_overflow_test.cmd");
    if (!cmdFile) {
        std::cout << "Failed to create command file." << std::endl;
        RemoveAllHooks();
        return;
    }

    // Create a visible batch script
    cmdFile << "@echo off" << std::endl;
    cmdFile << "echo ================================================================" << std::endl;
    cmdFile << "echo              BUFFER OVERFLOW CRASH DEMONSTRATION" << std::endl;
    cmdFile << "echo ================================================================" << std::endl;
    cmdFile << "echo This test will deliberately crash the program to demonstrate" << std::endl;
    cmdFile << "echo a buffer overflow vulnerability." << std::endl;
    cmdFile << "echo." << std::endl;
    cmdFile << "echo Press any key to begin the test..." << std::endl;
    cmdFile << "pause > nul" << std::endl;
    cmdFile << "echo." << std::endl;
    cmdFile << "echo Username prompt will appear. Enter the following:" << std::endl;
    cmdFile << "echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" << std::endl;
    cmdFile << "echo." << std::endl;
    cmdFile << "echo Then password prompt will appear. Enter the following:" << std::endl;
    cmdFile << "echo BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" << std::endl;
    cmdFile << "echo." << std::endl;
    cmdFile << "echo Starting test program now..." << std::endl;
    cmdFile << "echo ================================================================" << std::endl;
    cmdFile << "\"" << exePath << "\"" << std::endl;
    cmdFile << "echo." << std::endl;
    cmdFile << "echo ================================================================" << std::endl;
    cmdFile << "if %ERRORLEVEL% NEQ 0 (" << std::endl;
    cmdFile << "    echo TEST RESULT: CRASH DETECTED! (Exit code: %ERRORLEVEL%)" << std::endl;
    cmdFile << "    echo This confirms the buffer overflow vulnerability." << std::endl;
    cmdFile << ") else (" << std::endl;
    cmdFile << "    echo TEST RESULT: Program exited normally." << std::endl;
    cmdFile << "    echo No crash was detected. Try with longer input." << std::endl;
    cmdFile << ")" << std::endl;
    cmdFile << "echo ================================================================" << std::endl;
    cmdFile << "echo Press any key to close this window..." << std::endl;
    cmdFile << "pause > nul" << std::endl;
    cmdFile.close();

    // Execute the batch file in a visible window
    std::cout << "Launching interactive test window. Please follow the instructions there." << std::endl;
    std::cout << "When the window closes, we'll analyze the results..." << std::endl;

    SHELLEXECUTEINFOA shExecInfo = { 0 };
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = "open";
    shExecInfo.lpFile = "run_overflow_test.cmd";
    shExecInfo.lpParameters = "";
    shExecInfo.lpDirectory = NULL;
    shExecInfo.nShow = SW_SHOW;
    shExecInfo.hInstApp = NULL;

    if (ShellExecuteExA(&shExecInfo)) {
        // Wait for the batch process to complete
        WaitForSingleObject(shExecInfo.hProcess, INFINITE);

        // Get exit code
        DWORD exitCode = 0;
        GetExitCodeProcess(shExecInfo.hProcess, &exitCode);
        CloseHandle(shExecInfo.hProcess);

        // Analyze results
        if (exitCode != 0) {
            // Set red text color
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);

            std::cout << "\nCRASH CONFIRMED: The test program crashed with exit code " << exitCode << std::endl;
            std::cout << "Buffer overflow vulnerability successfully demonstrated!" << std::endl;

            // Reset text color
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        else {
            std::cout << "\nNo crash detected. The program exited normally." << std::endl;
            std::cout << "This could be due to security mitigations or compiler protections." << std::endl;
        }
    }
    else {
        std::cout << "Failed to launch test window: " << GetLastError() << std::endl;
    }

    // Clean up
    DeleteFileA("run_overflow_test.cmd");
    RemoveAllHooks();

    // Now run an analysis using the BufferOverflowDetector
    std::cout << "\nPerforming detailed analysis using BufferOverflowDetector..." << std::endl;

    // Create detector instance
    BufferOverflowDetector detector;
    detector.m_executablePath = exePath;
    detector.m_maxStringLength = 100;  // Test with strings up to 100 chars
    detector.m_increment = 10;         // Use larger increment for speed
    detector.m_timeout = 5;            // Short timeout
    detector.m_verbose = true;         // Detailed output
    detector.m_outputFile = "crash_test_results.json";

    // Test with specific input vectors
    bool result = detector.testVectorWithIncreasingInput("stdin");

    // Save and display results
    if (result) {
        std::cout << "\nBuffer overflow vulnerability confirmed programmatically!" << std::endl;
        detector.saveResults();
        std::cout << "Detailed results saved to: " << detector.m_outputFile << std::endl;

        // Display information about the smallest input that causes a crash
        size_t minCrashLen = ULONG_MAX;
        for (const auto& testResult : detector.m_results) {
            if ((testResult.status == "crashed" || testResult.status == "memory_corruption") &&
                testResult.inputLength < minCrashLen) {
                minCrashLen = testResult.inputLength;
            }
        }

        if (minCrashLen != ULONG_MAX) {
            std::cout << "Smallest input to trigger crash: " << minCrashLen << " bytes" << std::endl;
            std::cout << "Buffer overflow occurs after buffer size (10 bytes) is exceeded." << std::endl;
        }
    }
    else {
        std::cout << "\nAutomatic testing did not detect a buffer overflow vulnerability." << std::endl;
        std::cout << "The program may have protections or need different test parameters." << std::endl;
    }
}

int main() {
    int choice = 0;
    bool exit = false;

    printBanner();

    while (!exit) {
        printMenu();
        std::cin >> choice;

        // Clear any error flags
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            choice = 0;
        }

        switch (choice) {
        case 1:
            system("cls");  // Clear screen
            runBasicOverflowTest();
            break;

        case 2:
            system("cls");
            runEdgeCaseTest();
            break;

        case 3:
            system("cls");
            runFalsePositiveTest();
            break;

        case 4:
            system("cls");
            runPerformanceTest();
            break;

        case 5:
            system("cls");
            runCustomTest();
            break;

        case 6:
            system("cls");
            runExplicitCrashTest();
            break;

        case 7:
            exit = true;
            std::cout << "\nExiting BinaryRipper. Goodbye!" << std::endl;
            break;

        default:
            std::cout << "\nInvalid choice. Please try again." << std::endl;
        }

        if (!exit) {
            std::cout << "\nPress Enter to continue...";
            std::cin.ignore(1000, '\n');
            std::cin.get();
            system("cls");
            printBanner();
        }
    }

    return 0;
}