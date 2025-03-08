#pragma once
#include <string>
#include <vector>
#include <cstddef>
#include <Windows.h>
#include <memory>
#include <fstream>

class BufferOverflowDetector {
private:
    std::string m_executablePath; // Stores the file path to the executable being tested
    size_t m_maxStringLength;     // Maximum length of input string to test
    size_t m_increment;           // How much to increase input length between tests
    int m_timeout;                // Maximum time in seconds to allow for each test
    bool m_verbose;               // Controls detailed console output during testing
    std::string m_outputFile;     // File path where to save results

    struct TestResult {
        size_t inputLength;
        std::string status;        // "normal", "crashed", "memory_corruption", "error"
        DWORD returnCode;          // Windows process exit code
        std::string stdout_output;
        std::string stderr_output;
        std::string crashDetails;
        DWORD64 crashAddress;      // 64-bit address for Windows
        std::string vectorType;    // "stdin", "command_line", "file_input"
    };

    struct MemoryRegion {
        DWORD64 startAddress;
        DWORD64 endAddress;
        DWORD protection;         // Windows memory protection flags
        std::string moduleName;   // Associated module name if available
    };

    std::vector<TestResult> m_results;       // Store all test results
    std::vector<MemoryRegion> m_memoryMap;   // Store memory map of the process

public:
    BufferOverflowDetector();

    // Payload generation
    std::string generatePayload(size_t length);

    // Process creation and monitoring
    TestResult runProcess(HANDLE processHandle, HANDLE stdinWrite,
        HANDLE stdoutRead, HANDLE stderrRead);

    // Debug event handling
    bool handleDebugEvent(const DEBUG_EVENT& debugEvent, TestResult& result);

    // Input vector testing methods
    TestResult runWithStdin(const std::string& input);
    TestResult runWithCommandLineArgs(const std::string& arg);
    TestResult runWithFileInput(const std::string& fileContents,
        const std::string& filename = "test_input.txt");

    // Memory analysis
    void readMemoryMap(HANDLE processHandle);
    void analyzeCrash(TestResult& result, const EXCEPTION_RECORD& exceptionRecord);

    // Binary search for exact overflow point
    size_t findExactOverflowPoint(size_t start, size_t end, const std::string& vectorType);

    // Vector testing with increasing input sizes
    bool testVectorWithIncreasingInput(const std::string& vectorType);

    // Main testing method
    bool testExecutable();

    // Results saving
    void saveResults();
};