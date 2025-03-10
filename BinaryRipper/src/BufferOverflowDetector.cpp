#include "includes/BufferOverFlowDetector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <psapi.h>
#include <DbgHelp.h>

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Psapi.lib")

BufferOverflowDetector::BufferOverflowDetector()
    : m_executablePath(""),
    m_maxStringLength(1024),
    m_increment(16),
    m_timeout(5),
    m_verbose(true),
    m_outputFile("overflow_results.json") {
}

std::string BufferOverflowDetector::generatePayload(size_t length) {
    // Create a cyclic pattern that can be used to identify overflow positions
    std::string payload;
    payload.reserve(length);

    // Use a De Bruijn sequence pattern to create identifiable offsets
    const char* pattern = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const int patternLength = 26;

    for (size_t i = 0; i < length; i++) {
        int major = i % patternLength;
        int minor = (i / patternLength) % patternLength;
        int minorWrap = minor % 10;

        payload += pattern[major];
        if (i % 4 == 3) {
            payload += '0' + minorWrap;
        }
    }

    return payload.substr(0, length);
}

TestResult BufferOverflowDetector::runProcess(HANDLE processHandle, HANDLE stdinWrite,
    HANDLE stdoutRead, HANDLE stderrRead) {

    TestResult result;
    result.status = "normal";
    result.returnCode = 0;
    result.crashAddress = 0;

    // Resume the process (assuming it was created suspended)
    ResumeThread(GetThreadContext(processHandle, NULL));

    // Set up timeout
    DWORD waitResult = WaitForSingleObject(processHandle, m_timeout * 1000);

    if (waitResult == WAIT_TIMEOUT) {
        // Process did not complete within the timeout period
        result.status = "timeout";
        TerminateProcess(processHandle, 9999);
    }
    else {
        // Process completed - get the exit code
        GetExitCodeProcess(processHandle, &result.returnCode);

        // Read output from stdout and stderr
        char buffer[4096];
        DWORD bytesRead;

        // Read stdout
        std::string stdoutOutput;
        while (ReadFile(stdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            stdoutOutput += buffer;
        }
        result.stdout_output = stdoutOutput;

        // Read stderr
        std::string stderrOutput;
        while (ReadFile(stderrRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            stderrOutput += buffer;
        }
        result.stderr_output = stderrOutput;
    }

    return result;
}

bool BufferOverflowDetector::handleDebugEvent(const DEBUG_EVENT& debugEvent, TestResult& result) {
    switch (debugEvent.dwDebugEventCode) {
    case EXCEPTION_DEBUG_EVENT: {
        const EXCEPTION_RECORD& exception = debugEvent.u.Exception.ExceptionRecord;

        // Check if it's an access violation or other critical exception
        if (exception.ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
            exception.ExceptionCode == EXCEPTION_STACK_OVERFLOW ||
            exception.ExceptionCode == EXCEPTION_ARRAY_BOUNDS_EXCEEDED ||
            exception.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {

            result.status = "crashed";
            result.crashAddress = (DWORD64)exception.ExceptionAddress;

            // Analyze crash details
            analyzeCrash(result, exception);

            // Continue execution to let it terminate naturally
            return true;
        }

        // Handle other exceptions as needed
        break;
    }

    case EXIT_PROCESS_DEBUG_EVENT:
        // Process is exiting - check exit code
        result.returnCode = debugEvent.u.ExitProcess.dwExitCode;
        if (result.returnCode != 0 && result.status == "normal") {
            result.status = "error";
        }
        break;
    }

    return false;
}

TestResult BufferOverflowDetector::runWithStdin(const std::string& input) {
    TestResult result;
    result.vectorType = "stdin";
    result.inputLength = input.length();

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE stdinRead, stdinWrite, stdoutRead, stdoutWrite, stderrRead, stderrWrite;

    // Create pipes
    if (!CreatePipe(&stdinRead, &stdinWrite, &saAttr, 0) ||
        !CreatePipe(&stdoutRead, &stdoutWrite, &saAttr, 0) ||
        !CreatePipe(&stderrRead, &stderrWrite, &saAttr, 0)) {

        result.status = "error";
        result.crashDetails = "Failed to create pipes for process I/O";
        return result;
    }

    // Ensure the read/write handles to the pipes aren't inherited
    SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);

    // Start process with pipes
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.hStdInput = stdinRead;
    si.hStdOutput = stdoutWrite;
    si.hStdError = stderrWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi;

    if (!CreateProcessA(
        m_executablePath.c_str(),      // Application name
        NULL,                           // Command line
        NULL,                           // Process security attributes
        NULL,                           // Thread security attributes
        TRUE,                          // Inherit handles
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, // Creation flags
        NULL,                           // Environment
        NULL,                           // Current directory
        &si,                            // Startup info
        &pi                             // Process info
    )) {
        result.status = "error";
        result.crashDetails = "Failed to create process: " + std::to_string(GetLastError());

        CloseHandle(stdinRead);
        CloseHandle(stdinWrite);
        CloseHandle(stdoutRead);
        CloseHandle(stdoutWrite);
        CloseHandle(stderrRead);
        CloseHandle(stderrWrite);

        return result;
    }

    // Write the input to stdin
    DWORD bytesWritten;
    WriteFile(stdinWrite, input.c_str(), static_cast<DWORD>(input.length()), &bytesWritten, NULL);
    CloseHandle(stdinWrite);  // Close the write handle to signal EOF

    // Read memory map now that the process is running
    readMemoryMap(pi.hProcess);

    // Debug loop
    DEBUG_EVENT debugEvent = { 0 };
    bool done = false;

    while (!done) {
        if (WaitForDebugEvent(&debugEvent, 1000)) {
            // Handle debug event
            bool shouldBreak = handleDebugEvent(debugEvent, result);

            // Continue the debugging loop
            ContinueDebugEvent(
                debugEvent.dwProcessId,
                debugEvent.dwThreadId,
                shouldBreak ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE
            );

            if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                done = true;
            }
        }
        else if (GetLastError() == ERROR_SEM_TIMEOUT) {
            // Timeout waiting for debug event
            result.status = "timeout";
            TerminateProcess(pi.hProcess, 9999);
            done = true;
        }
    }

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(stdinRead);
    CloseHandle(stdoutRead);
    CloseHandle(stdoutWrite);
    CloseHandle(stderrRead);
    CloseHandle(stderrWrite);

    return result;
}

TestResult BufferOverflowDetector::runWithCommandLineArgs(const std::string& arg) {
    TestResult result;
    result.vectorType = "command_line";
    result.inputLength = arg.length();

    // Construct command line
    std::string commandLine = m_executablePath + " " + arg;

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE stdoutRead, stdoutWrite, stderrRead, stderrWrite;

    // Create pipes for stdout and stderr
    if (!CreatePipe(&stdoutRead, &stdoutWrite, &saAttr, 0) ||
        !CreatePipe(&stderrRead, &stderrWrite, &saAttr, 0)) {

        result.status = "error";
        result.crashDetails = "Failed to create pipes for process I/O";
        return result;
    }

    // Ensure the read handles to the pipe aren't inherited
    SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);

    // Start process with redirected output
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.hStdOutput = stdoutWrite;
    si.hStdError = stderrWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi;

    // Create a writable copy of the command line
    char* cmdLine = _strdup(commandLine.c_str());

    if (!CreateProcessA(
        NULL,                           // Application name (NULL to use command line)
        cmdLine,                        // Command line
        NULL,                           // Process security attributes
        NULL,                           // Thread security attributes
        TRUE,                           // Inherit handles
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, // Creation flags
        NULL,                           // Environment
        NULL,                           // Current directory
        &si,                            // Startup info
        &pi                             // Process info
    )) {
        result.status = "error";
        result.crashDetails = "Failed to create process: " + std::to_string(GetLastError());

        free(cmdLine);
        CloseHandle(stdoutRead);
        CloseHandle(stdoutWrite);
        CloseHandle(stderrRead);
        CloseHandle(stderrWrite);

        return result;
    }

    free(cmdLine);

    // Read memory map now that the process is running
    readMemoryMap(pi.hProcess);

    // Debug loop
    DEBUG_EVENT debugEvent = { 0 };
    bool done = false;

    while (!done) {
        if (WaitForDebugEvent(&debugEvent, 1000)) {
            // Handle debug event
            bool shouldBreak = handleDebugEvent(debugEvent, result);

            // Continue the debugging loop
            ContinueDebugEvent(
                debugEvent.dwProcessId,
                debugEvent.dwThreadId,
                shouldBreak ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE
            );

            if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                done = true;
            }
        }
        else if (GetLastError() == ERROR_SEM_TIMEOUT) {
            // Timeout waiting for debug event
            result.status = "timeout";
            TerminateProcess(pi.hProcess, 9999);
            done = true;
        }
    }

    // Read output from stdout and stderr
    char buffer[4096];
    DWORD bytesRead;

    // Read stdout
    std::string stdoutOutput;
    while (ReadFile(stdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        stdoutOutput += buffer;
    }
    result.stdout_output = stdoutOutput;

    // Read stderr
    std::string stderrOutput;
    while (ReadFile(stderrRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        stderrOutput += buffer;
    }
    result.stderr_output = stderrOutput;

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(stdoutRead);
    CloseHandle(stdoutWrite);
    CloseHandle(stderrRead);
    CloseHandle(stderrWrite);

    return result;
}

TestResult BufferOverflowDetector::runWithFileInput(const std::string& fileContents,
    const std::string& filename) {

    TestResult result;
    result.vectorType = "file_input";
    result.inputLength = fileContents.length();

    // Create test file
    std::ofstream testFile(filename, std::ios::binary);
    if (!testFile) {
        result.status = "error";
        result.crashDetails = "Failed to create test input file";
        return result;
    }

    testFile.write(fileContents.c_str(), fileContents.length());
    testFile.close();

    // Set up process creation
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE stdoutRead, stdoutWrite, stderrRead, stderrWrite;

    // Create pipes for stdout and stderr
    if (!CreatePipe(&stdoutRead, &stdoutWrite, &saAttr, 0) ||
        !CreatePipe(&stderrRead, &stderrWrite, &saAttr, 0)) {

        result.status = "error";
        result.crashDetails = "Failed to create pipes for process I/O";
        return result;
    }

    // Ensure the read handles to the pipe aren't inherited
    SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);

    // Start process with redirected output
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.hStdOutput = stdoutWrite;
    si.hStdError = stderrWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi;

    // Construct command line with the file as an argument
    std::string commandLine = m_executablePath + " " + filename;
    char* cmdLine = _strdup(commandLine.c_str());

    if (!CreateProcessA(
        NULL,                           // Application name
        cmdLine,                        // Command line
        NULL,                           // Process security attributes
        NULL,                           // Thread security attributes
        TRUE,                           // Inherit handles
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, // Creation flags
        NULL,                           // Environment
        NULL,                           // Current directory
        &si,                            // Startup info
        &pi                             // Process info
    )) {
        result.status = "error";
        result.crashDetails = "Failed to create process: " + std::to_string(GetLastError());

        free(cmdLine);
        CloseHandle(stdoutRead);
        CloseHandle(stdoutWrite);
        CloseHandle(stderrRead);
        CloseHandle(stderrWrite);

        return result;
    }

    free(cmdLine);

    // Read memory map now that the process is running
    readMemoryMap(pi.hProcess);

    // Debug loop
    DEBUG_EVENT debugEvent = { 0 };
    bool done = false;

    while (!done) {
        if (WaitForDebugEvent(&debugEvent, 1000)) {
            // Handle debug event
            bool shouldBreak = handleDebugEvent(debugEvent, result);

            // Continue the debugging loop
            ContinueDebugEvent(
                debugEvent.dwProcessId,
                debugEvent.dwThreadId,
                shouldBreak ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE
            );

            if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                done = true;
            }
        }
        else if (GetLastError() == ERROR_SEM_TIMEOUT) {
            // Timeout waiting for debug event
            result.status = "timeout";
            TerminateProcess(pi.hProcess, 9999);
            done = true;
        }
    }

    // Read output from stdout and stderr
    char buffer[4096];
    DWORD bytesRead;

    // Read stdout
    std::string stdoutOutput;
    while (ReadFile(stdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        stdoutOutput += buffer;
    }
    result.stdout_output = stdoutOutput;

    // Read stderr
    std::string stderrOutput;
    while (ReadFile(stderrRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        stderrOutput += buffer;
    }
    result.stderr_output = stderrOutput;

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(stdoutRead);
    CloseHandle(stdoutWrite);
    CloseHandle(stderrRead);
    CloseHandle(stderrWrite);

    // Delete the test file
    DeleteFileA(filename.c_str());

    return result;
}

void BufferOverflowDetector::readMemoryMap(HANDLE processHandle) {
    m_memoryMap.clear();

    // Get list of modules in the process
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(processHandle, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            char szModName[MAX_PATH];

            // Get module info
            if (GetModuleInformation(processHandle, hMods[i], &modInfo, sizeof(modInfo)) &&
                GetModuleFileNameExA(processHandle, hMods[i], szModName, sizeof(szModName))) {

                MemoryRegion region;
                region.startAddress = (DWORD64)modInfo.lpBaseOfDll;
                region.endAddress = (DWORD64)modInfo.lpBaseOfDll + modInfo.SizeOfImage;
                region.protection = 0; // Not directly accessible via GetModuleInformation

                // Extract just the module name from the path
                std::string fullPath(szModName);
                size_t lastSlash = fullPath.find_last_of("\\/");
                if (lastSlash != std::string::npos) {
                    region.moduleName = fullPath.substr(lastSlash + 1);
                }
                else {
                    region.moduleName = fullPath;
                }

                m_memoryMap.push_back(region);
            }
        }
    }

    // Now enumerate all memory regions for completeness
    MEMORY_BASIC_INFORMATION mbi;
    DWORD64 address = 0;

    while (VirtualQueryEx(processHandle, (LPCVOID)address, &mbi, sizeof(mbi))) {
        // Only add committed memory regions
        if (mbi.State == MEM_COMMIT) {
            // Check if this region is already covered by a module
            bool inModule = false;
            for (const auto& region : m_memoryMap) {
                if ((DWORD64)mbi.BaseAddress >= region.startAddress &&
                    (DWORD64)mbi.BaseAddress + mbi.RegionSize <= region.endAddress) {
                    inModule = true;
                    break;
                }
            }

            // If not in a module, add it as a separate memory region
            if (!inModule) {
                MemoryRegion region;
                region.startAddress = (DWORD64)mbi.BaseAddress;
                region.endAddress = (DWORD64)mbi.BaseAddress + mbi.RegionSize;
                region.protection = mbi.Protect;
                region.moduleName = ""; // Not associated with any module

                m_memoryMap.push_back(region);
            }
        }

        // Move to the next memory region
        address = (DWORD64)mbi.BaseAddress + mbi.RegionSize;
    }
}

void BufferOverflowDetector::analyzeCrash(TestResult& result, const EXCEPTION_RECORD& exceptionRecord) {
    // Identify the module/region where the crash occurred
    DWORD64 crashAddr = (DWORD64)exceptionRecord.ExceptionAddress;

    for (const auto& region : m_memoryMap) {
        if (crashAddr >= region.startAddress && crashAddr < region.endAddress) {
            // Found the region containing the crash address
            std::stringstream ss;

            ss << "Crash at address 0x" << std::hex << crashAddr;

            if (!region.moduleName.empty()) {
                ss << " in module " << region.moduleName;
                ss << " (offset: 0x" << std::hex << (crashAddr - region.startAddress) << ")";
            }

            // Add exception information
            ss << "\nException code: 0x" << std::hex << exceptionRecord.ExceptionCode;

            // Specific information for access violations
            if (exceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
                ss << "\nAccess violation type: ";
                switch (exceptionRecord.ExceptionInformation[0]) {
                case 0: ss << "read"; break;
                case 1: ss << "write"; break;
                case 8: ss << "execute"; break;
                default: ss << "unknown"; break;
                }

                ss << "\nViolation address: 0x" << std::hex << exceptionRecord.ExceptionInformation[1];
            }

            result.crashDetails = ss.str();
            break;
        }
    }

    if (result.crashDetails.empty()) {
        result.crashDetails = "Crash at unknown address: 0x" +
            std::to_string(crashAddr);
    }
}

size_t BufferOverflowDetector::findExactOverflowPoint(size_t start, size_t end, const std::string& vectorType) {
    if (start >= end) {
        return start;
    }

    size_t mid = start + (end - start) / 2;
    std::string payload = generatePayload(mid);
    TestResult result;

    // Run with the appropriate vector type
    if (vectorType == "stdin") {
        result = runWithStdin(payload);
    }
    else if (vectorType == "command_line") {
        result = runWithCommandLineArgs(payload);
    }
    else if (vectorType == "file_input") {
        result = runWithFileInput(payload);
    }
    else {
        // Unknown vector type
        return start;
    }

    if (result.status == "crashed" || result.status == "memory_corruption") {
        // Overflow occurred at this length, try smaller
        return findExactOverflowPoint(start, mid - 1, vectorType);
    }
    else {
        // No overflow at this length, try larger
        return findExactOverflowPoint(mid + 1, end, vectorType);
    }
}

bool BufferOverflowDetector::testVectorWithIncreasingInput(const std::string& vectorType) {
    bool foundOverflow = false;
    size_t minCrashLength = m_maxStringLength;

    // Test with increasing input sizes
    for (size_t length = 1; length <= m_maxStringLength; length += m_increment) {
        std::string payload = generatePayload(length);
        TestResult result;

        if (m_verbose) {
            std::cout << "Testing " << vectorType << " with input length " << length << std::endl;
        }

        // Run with the appropriate vector type
        if (vectorType == "stdin") {
            result = runWithStdin(payload);
        }
        else if (vectorType == "command_line") {
            result = runWithCommandLineArgs(payload);
        }
        else if (vectorType == "file_input") {
            result = runWithFileInput(payload);
        }
        else {
            std::cerr << "Unknown vector type: " << vectorType << std::endl;
            return false;
        }

        // Store the result
        m_results.push_back(result);

        // Check if we found an overflow
        if (result.status == "crashed" || result.status == "memory_corruption") {
            if (m_verbose) {
                std::cout << "Found potential overflow at length " << length << std::endl;
                std::cout << result.crashDetails << std::endl;
            }

            foundOverflow = true;
            minCrashLength = std::min(minCrashLength, length);

            // Stop testing larger inputs once we find a crash
            break;
        }
    }

    // If we found an overflow, perform binary search to find the exact point
    if (foundOverflow && minCrashLength > 1) {
        size_t exactPoint = findExactOverflowPoint(1, minCrashLength, vectorType);

        if (m_verbose) {
            std::cout << "Exact overflow point for " << vectorType << ": " << exactPoint << " bytes" << std::endl;
        }

        // Add this exact point result
        std::string payload = generatePayload(exactPoint);
        TestResult result;

        if (vectorType == "stdin") {
            result = runWithStdin(payload);
        }
        else if (vectorType == "command_line") {
            result = runWithCommandLineArgs(payload);
        }
        else if (vectorType == "file_input") {
            result = runWithFileInput(payload);
        }

        m_results.push_back(result);
    }

    return foundOverflow;
}

bool BufferOverflowDetector::testExecutable() {
    if (m_executablePath.empty()) {
        std::cerr << "Error: No executable path specified." << std::endl;
        return false;
    }

    // Clear previous results
    m_results.clear();

    // Test with standard input
    bool stdinOverflow = testVectorWithIncreasingInput("stdin");

    // Test with command-line arguments
    bool cmdLineOverflow = testVectorWithIncreasingInput("command_line");

    // Test with file input
    bool fileOverflow = testVectorWithIncreasingInput("file_input");

    // Return true if any overflow was found
    return stdinOverflow || cmdLineOverflow || fileOverflow;
}

void BufferOverflowDetector::saveResults() {
    std::ofstream outFile(m_outputFile);
    if (!outFile) {
        std::cerr << "Error: Failed to open output file: " << m_outputFile << std::endl;
        return;
    }

    // Start JSON output
    outFile << "{\n";
    outFile << "  \"executable\": \"" << m_executablePath << "\",\n";
    outFile << "  \"results\": [\n";

    // Output each result
    for (size_t i = 0; i < m_results.size(); i++) {
        const auto& result = m_results[i];

        outFile << "    {\n";
        outFile << "      \"vectorType\": \"" << result.vectorType << "\",\n";
        outFile << "      \"inputLength\": " << result.inputLength << ",\n";
        outFile << "      \"status\": \"" << result.status << "\",\n";
        outFile << "      \"returnCode\": " << result.returnCode << ",\n";

        // Escape special characters in strings
        std::string escapedCrashDetails = result.crashDetails;
        std::string escapedStdout = result.stdout_output;
        std::string escapedStderr = result.stderr_output;

        // Replace backslashes, quotes, and control characters
        auto escapeJson = [](std::string& str) {
            size_t pos = 0;
            while ((pos = str.find_first_of("\"\\\b\f\n\r\t", pos)) != std::string::npos) {
                switch (str[pos]) {
                case '\"': str.replace(pos, 1, "\\\""); pos += 2; break;
                case '\\': str.replace(pos, 1, "\\\\"); pos += 2; break;
                case '\b': str.replace(pos, 1, "\\b"); pos += 2; break;
                case '\f': str.replace(pos, 1, "\\f"); pos += 2; break;
                case '\n': str.replace(pos, 1, "\\n"); pos += 2; break;
                case '\r': str.replace(pos, 1, "\\r"); pos += 2; break;
                case '\t': str.replace(pos, 1, "\\t"); pos += 2; break;
                default: pos++; break;
                }
            }
            };

        escapeJson(escapedCrashDetails);
        escapeJson(escapedStdout);
        escapeJson(escapedStderr);

        outFile << "      \"crashDetails\": \"" << escapedCrashDetails << "\",\n";
        outFile << "      \"crashAddress\": \"0x" << std::hex << result.crashAddress << "\",\n";
        outFile << "      \"stdout\": \"" << escapedStdout << "\",\n";
        outFile << "      \"stderr\": \"" << escapedStderr << "\"\n";

        // Add comma if not the last item
        outFile << "    }" << (i < m_results.size() - 1 ? "," : "") << "\n";
    }

    // Close the JSON structure
    outFile << "  ]\n";
    outFile << "}\n";

    outFile.close();

    if (m_verbose) {
        std::cout << "Results saved to: " << m_outputFile << std::endl;
    }
}