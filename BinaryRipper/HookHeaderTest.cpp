#include "hook.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <windows.h>
#include <fstream>
#include <string>

// Configure logging to both console and file
std::ofstream logFile;

void Log(const std::string& message) {
    std::cout << message << std::endl;
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.flush();
    }
}

// Simple test function
int __stdcall OriginalFunction(int a, int b) {
    Log("Original function called with " + std::to_string(a) + " and " + std::to_string(b));
    return a + b;
}

// Hooked version
int __stdcall HookedFunction(int a, int b) {
    Log("Hooked function called with " + std::to_string(a) + " and " + std::to_string(b));

    // Get the hook instance
    auto hookInstance = GetHookInstance();

    // Submit async work to thread pool
    hookInstance->submitCallback([]() {
        Log("Async callback running in thread pool, ID: " +
            std::to_string(GetCurrentThreadId()));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        });

    return a * b; // Different behavior
}

// Windows API hook tests
typedef int (WINAPI* MessageBoxAType)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxAType originalMessageBoxA = nullptr;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    Log("MessageBoxA hooked! Original text: " + std::string(lpText));
    return originalMessageBoxA(hWnd, "This message was modified by the hook", lpCaption, uType);
}

typedef BOOL(WINAPI* WriteFileType)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
WriteFileType originalWriteFile = nullptr;

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    Log("WriteFile hooked! Intercepted write of " + std::to_string(nNumberOfBytesToWrite) + " bytes");

    // We'll modify the data being written - convert to uppercase if it's text
    if (lpBuffer && nNumberOfBytesToWrite > 0) {
        char* buffer = new char[nNumberOfBytesToWrite + 1];
        memcpy(buffer, lpBuffer, nNumberOfBytesToWrite);
        buffer[nNumberOfBytesToWrite] = '\0';

        // Try to convert to uppercase (assuming it's text)
        for (DWORD i = 0; i < nNumberOfBytesToWrite; i++) {
            if (isalpha(buffer[i])) {
                buffer[i] = toupper(buffer[i]);
            }
        }

        // Call original with modified buffer
        BOOL result = originalWriteFile(hFile, buffer, nNumberOfBytesToWrite,
            lpNumberOfBytesWritten, lpOverlapped);

        delete[] buffer;
        return result;
    }

    return originalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
        lpNumberOfBytesWritten, lpOverlapped);
}

// Performance test function
void runPerformanceTest(int iterations) {
    int sum = 0;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        sum += OriginalFunction(i, i + 1);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    Log("Performance test: " + std::to_string(iterations) + " iterations in " +
        std::to_string(duration.count()) + " microseconds");
    Log("Average per call: " + std::to_string((double)duration.count() / iterations) +
        " microseconds");
}

// Concurrent test function
void runConcurrentTest(int threadCount, int callsPerThread) {
    std::vector<std::thread> threads;

    for (int t = 0; t < threadCount; t++) {
        threads.push_back(std::thread([t, callsPerThread]() {
            Log("Thread " + std::to_string(t) + " started, ID: " +
                std::to_string(GetCurrentThreadId()));

            for (int i = 0; i < callsPerThread; i++) {
                int result = OriginalFunction(t, i);
                // Log("Thread " + std::to_string(t) + " call " + std::to_string(i) + 
                //    " result: " + std::to_string(result));
            }
            }));
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

int main() {
    // Configure console for better visibility
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);

    COORD bufferSize;
    bufferSize.X = csbi.dwSize.X;
    bufferSize.Y = 9000; // Much larger buffer
    SetConsoleScreenBufferSize(hConsole, bufferSize);

    // Open log file
    logFile.open("hook_test_log.txt");
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
    }

    // Get the hook instance
    ThreadPoolHook* hookManager = ThreadPoolHook::getInstance();

    Log("==========================================");
    Log("     HOOK IMPLEMENTATION TEST SUITE      ");

    // Format current time
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::system_clock::to_time_t(now);
    char timeBuffer[26];
    ctime_s(timeBuffer, sizeof(timeBuffer), &currentTime);
    Log("     " + std::string(timeBuffer));

    Log("==========================================\n");

    //====================================================
    // Test 1: Basic Hook Functionality
    //====================================================
    Log("TEST 1: BASIC HOOK FUNCTIONALITY");
    Log("------------------------------------------");

    // Call original function before hooking
    int result1 = OriginalFunction(5, 7);
    Log("Result before hook: " + std::to_string(result1));

    // Install the hook
    int (*originalFunc)(int, int) = nullptr;
    if (hookManager->hook(OriginalFunction, HookedFunction, &originalFunc)) {
        Log("Hook installed successfully");
    }
    else {
        Log("Failed to install hook");
        return 1;
    }

    // Call the function after hooking
    int result2 = OriginalFunction(5, 7);
    Log("Result after hook: " + std::to_string(result2));

    // Wait for any async callbacks to complete
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Remove the hook
    if (hookManager->unhook(OriginalFunction)) {
        Log("Hook removed successfully");
    }
    else {
        Log("Failed to remove hook");
    }

    // Call the function after unhooking
    int result3 = OriginalFunction(5, 7);
    Log("Result after unhook: " + std::to_string(result3));

    //====================================================
    // Test 2: Windows API Hook Testing
    //====================================================
    Log("\nTEST 2: WINDOWS API HOOK TESTING");
    Log("------------------------------------------");

    // Hook MessageBoxA
    Log("2.1: MessageBoxA Hook Test");
    if (hookManager->hook(MessageBoxA, HookedMessageBoxA, &originalMessageBoxA)) {
        Log("MessageBoxA hook installed");

        // Call the hooked function - uncomment to see actual message box
        MessageBoxA(NULL, "Original message", "Hook Test", MB_OK);
        Log("MessageBoxA showed a modified message");

        // Remove the hook
        hookManager->unhook(MessageBoxA);
        Log("MessageBoxA hook removed");
    }
    else {
        Log("Failed to hook MessageBoxA");
    }
    MessageBoxA(NULL, "Test again after unhooking", "Normal MessageBox", MB_OK);

    // Hook WriteFile
    Log("\n2.2: WriteFile Hook Test");
    if (hookManager->hook(WriteFile, HookedWriteFile, &originalWriteFile)) {
        Log("WriteFile hook installed");

        // Test writing to a file with the hook
        HANDLE hFile = CreateFileA("hooktest.txt", GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile != INVALID_HANDLE_VALUE) {
            const char* testText = "This text should be converted to uppercase by the hook.";
            DWORD bytesWritten = 0;

            if (WriteFile(hFile, testText, (DWORD)strlen(testText), &bytesWritten, NULL)) {
                Log("Wrote " + std::to_string(bytesWritten) + " bytes to hooktest.txt");
            }
            else {
                Log("Failed to write to file, error: " + std::to_string(GetLastError()));
            }

            CloseHandle(hFile);

            // Open and read the file to verify uppercase conversion
            std::ifstream readFile("hooktest.txt");
            if (readFile.is_open()) {
                std::string content((std::istreambuf_iterator<char>(readFile)),
                    std::istreambuf_iterator<char>());
                Log("File content: " + content);
                readFile.close();
            }
        }
        else {
            Log("Failed to create file, error: " + std::to_string(GetLastError()));
        }

        // Remove the hook
        if (hookManager->unhook(WriteFile)) {
            Log("WriteFile hook removed");
        }
        else {
            Log("Failed to remove WriteFile hook");
        }
    }
    else {
        Log("Failed to hook WriteFile");
    }

    //====================================================
    // Test 3: Performance Testing
    //====================================================
    Log("\nTEST 3: PERFORMANCE TESTING");
    Log("------------------------------------------");

    // Test without hook
    Log("3.1: Performance without hook");
    runPerformanceTest(10000);

    // Test with hook
    Log("\n3.2: Performance with hook");
    hookManager->hook(OriginalFunction, HookedFunction, &originalFunc);
    runPerformanceTest(10000);
    hookManager->unhook(OriginalFunction);

    //====================================================
    // Test 4: Concurrent Testing
    //====================================================
    Log("\nTEST 4: CONCURRENT TESTING");
    Log("------------------------------------------");

    // Test concurrency without hook
    Log("4.1: Concurrency without hook");
    runConcurrentTest(5, 100);

    // Test concurrency with hook
    Log("\n4.2: Concurrency with hook");
    hookManager->hook(OriginalFunction, HookedFunction, &originalFunc);
    runConcurrentTest(5, 100);
    hookManager->unhook(OriginalFunction);

    //====================================================
    // Test 5: Hook Chaining (Multiple Hooks on Same Function)
    //====================================================
    Log("\nTEST 5: HOOK CHAINING");
    Log("------------------------------------------");

    // Define a second hook function that will replace the first one
    auto secondHook = [](int a, int b) -> int {
        Log("Second hook called with " + std::to_string(a) + " and " + std::to_string(b));
        return a - b; // Subtraction instead of multiplication
        };

    int (*originalAgain)(int, int) = nullptr;

    // Install first hook
    hookManager->hook(OriginalFunction, HookedFunction, &originalFunc);
    Log("First hook installed (multiply)");

    // Test first hook
    int chainResult1 = OriginalFunction(10, 5);
    Log("Result with first hook: " + std::to_string(chainResult1));

    // Clean up for next tests
    hookManager->unhookAll();
    Log("All hooks removed");

    //====================================================
    // Cleanup and exit
    //====================================================
    Log("\nAll tests completed. Cleaning up...");

    // Clean up the hook manager
    ThreadPoolHook::cleanup();

    // Close the log file
    if (logFile.is_open()) {
        logFile.close();
    }

    // Keep console window open until user presses a key
    Log("\nPress any key to exit...");
    system("pause");

    return 0;
}