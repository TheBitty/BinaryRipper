#include "includes/hook.h"
#include <Windows.h>
#include <unordered_map>
#include <mutex>
#include <string>
#include <sstream>
#include <fstream>
#include <cstring>
#include <vector>
#include <iomanip>
#include <ctime>

// Forward declarations to avoid double-definitions
typedef void* (*MallocFuncType)(size_t);
typedef void (*FreeFuncType)(void*);
typedef void* (*ReallocFuncType)(void*, size_t);
typedef void* (*CallocFuncType)(size_t, size_t);
typedef char* (*StrcpyFuncType)(char*, const char*);
typedef char* (*StrncpyFuncType)(char*, const char*, size_t);
typedef char* (*StrcatFuncType)(char*, const char*);
typedef char* (*StrncatFuncType)(char*, const char*, size_t);
typedef void* (*MemcpyFuncType)(void*, const void*, size_t);
typedef void* (*MemmoveFuncType)(void*, const void*, size_t);
typedef void* (*MemsetFuncType)(void*, int, size_t);

// Original function pointers
MallocFuncType original_malloc = nullptr;
FreeFuncType original_free = nullptr;
ReallocFuncType original_realloc = nullptr;
CallocFuncType original_calloc = nullptr;
StrcpyFuncType original_strcpy = nullptr;
StrncpyFuncType original_strncpy = nullptr;
StrcatFuncType original_strcat = nullptr;
StrncatFuncType original_strncat = nullptr;
MemcpyFuncType original_memcpy = nullptr;
MemmoveFuncType original_memmove = nullptr;
MemsetFuncType original_memset = nullptr;

// Class for memory tracking
class MemoryTracker {
private:
    struct BufferInfo {
        size_t size;
        std::string allocStack;
        std::time_t allocTime;
        bool isFreed;
    };

    std::unordered_map<void*, BufferInfo> m_buffers;
    std::mutex m_mutex;
    std::ofstream m_logFile;
    bool m_verbose;

    std::string m_logFilePath;
    size_t m_totalAllocated;
    size_t m_totalFreed;
    size_t m_peakUsage;

    // Capture stack trace - simplified version
    std::string captureStackTrace() {
        // This is a simplified placeholder. A real implementation would use:
        // - Windows: StackWalk64, CaptureStackBackTrace, SymFromAddr
        // - In a real implementation, you'd want to use DbgHelp.lib functions
        return "Stack trace not implemented in this version";
    }

public:
    MemoryTracker() : m_verbose(false), m_totalAllocated(0), m_totalFreed(0), m_peakUsage(0) {
        m_logFilePath = "memory_hooks.log";
        m_logFile.open(m_logFilePath);

        if (m_logFile.is_open()) {
            m_logFile << "BinaryRipper Memory Hook Log\n";
            m_logFile << "===========================\n";
            m_logFile << "Started at: " << getCurrentTimestamp() << "\n\n";
        }
    }

    ~MemoryTracker() {
        if (m_logFile.is_open()) {
            reportLeaks();
            m_logFile << "\nMemory hook log closed at: " << getCurrentTimestamp() << "\n";
            m_logFile.close();
        }
    }

    std::string getCurrentTimestamp() {
        std::time_t now = std::time(nullptr);
        std::tm tm;
        localtime_s(&tm, &now);

        char buffer[64];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
        return buffer;
    }

    void trackAllocation(void* ptr, size_t size) {
        if (!ptr) return;

        std::lock_guard<std::mutex> lock(m_mutex);

        BufferInfo info;
        info.size = size;
        info.allocStack = captureStackTrace();
        info.allocTime = std::time(nullptr);
        info.isFreed = false;

        m_buffers[ptr] = info;

        m_totalAllocated += size;
        size_t currentUsage = m_totalAllocated - m_totalFreed;
        if (currentUsage > m_peakUsage) {
            m_peakUsage = currentUsage;
        }

        if (m_verbose && m_logFile.is_open()) {
            m_logFile << "[" << getCurrentTimestamp() << "] Allocated " << size
                << " bytes at " << ptr << std::endl;
        }
    }

    void trackFree(void* ptr) {
        if (!ptr) return;

        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_buffers.find(ptr);
        if (it != m_buffers.end() && !it->second.isFreed) {
            // Mark as freed but keep in map for double-free detection
            it->second.isFreed = true;
            m_totalFreed += it->second.size;

            if (m_verbose && m_logFile.is_open()) {
                m_logFile << "[" << getCurrentTimestamp() << "] Freed " << it->second.size
                    << " bytes at " << ptr << std::endl;
            }
        }
        else if (it != m_buffers.end() && it->second.isFreed) {
            // Detect double-free
            logIssue("Double free detected", ptr);
        }
        else {
            // Freeing untracked memory
            logIssue("Freeing untracked memory", ptr);
        }
    }

    void trackRealloc(void* oldPtr, void* newPtr, size_t newSize) {
        if (oldPtr) {
            trackFree(oldPtr);
        }
        if (newPtr) {
            trackAllocation(newPtr, newSize);
        }
    }

    bool checkBufferOverflow(const void* dest, const void* src, size_t count, const char* operation) {
        if (!dest) return false;

        std::lock_guard<std::mutex> lock(m_mutex);

        // Find the destination buffer
        void* destNonConst = const_cast<void*>(dest); // We need non-const for map lookup
        auto it = m_buffers.find(destNonConst);

        if (it == m_buffers.end()) {
            // Buffer not tracked - could be stack-based or allocated by other means
            // We can't reliably check for overflow in this case
            return false;
        }

        if (it->second.isFreed) {
            // Using freed memory
            logIssue("Use after free detected", destNonConst);
            return true;
        }

        // Check if the operation would exceed buffer boundaries
        if (count > it->second.size) {
            std::stringstream ss;
            ss << "Potential buffer overflow in " << operation
                << ": copying " << count << " bytes into a buffer of size " << it->second.size;
            logIssue(ss.str(), destNonConst);
            return true;
        }

        return false;
    }

    bool checkStringSafety(const char* dest, const char* src, const char* operation) {
        if (!dest || !src) return false;

        std::lock_guard<std::mutex> lock(m_mutex);

        size_t srcLen = strlen(src);

        // Find the destination buffer
        void* destNonConst = const_cast<void*>(static_cast<const void*>(dest));
        auto it = m_buffers.find(destNonConst);

        if (it == m_buffers.end()) {
            // Buffer not tracked - could be stack-based
            return false;
        }

        if (it->second.isFreed) {
            // Using freed memory
            logIssue("Use after free detected in string operation", destNonConst);
            return true;
        }

        // For operations like strcpy, the null terminator must fit too
        if (srcLen + 1 > it->second.size) {
            std::stringstream ss;
            ss << "Potential buffer overflow in " << operation
                << ": copying " << srcLen + 1 << " bytes (including null) into a buffer of size "
                << it->second.size;
            logIssue(ss.str(), destNonConst);
            return true;
        }

        return false;
    }

    void setVerbose(bool verbose) {
        m_verbose = verbose;
    }

    void setLogFile(const std::string& logFilePath) {
        if (m_logFile.is_open()) {
            m_logFile.close();
        }

        m_logFilePath = logFilePath;
        m_logFile.open(m_logFilePath);

        if (m_logFile.is_open()) {
            m_logFile << "BinaryRipper Memory Hook Log\n";
            m_logFile << "===========================\n";
            m_logFile << "Started at: " << getCurrentTimestamp() << "\n\n";
        }
    }

    void logIssue(const std::string& issue, void* address) {
        if (m_logFile.is_open()) {
            m_logFile << "[" << getCurrentTimestamp() << "] ISSUE: " << issue
                << " at address " << address << std::endl;
        }

        // Also send to standard error for immediate feedback
        std::cerr << "MEMORY HOOK: " << issue << " at address " << address << std::endl;
    }

    void reportLeaks() {
        std::lock_guard<std::mutex> lock(m_mutex);

        size_t leakCount = 0;
        size_t leakSize = 0;

        m_logFile << "\nMemory Leak Report\n";
        m_logFile << "=================\n";

        for (const auto& pair : m_buffers) {
            if (!pair.second.isFreed) {
                leakCount++;
                leakSize += pair.second.size;

                m_logFile << "Leak: " << pair.second.size << " bytes at " << pair.first
                    << " (allocated at " << ctime(&pair.second.allocTime) << ")\n";
            }
        }

        m_logFile << "\nTotal: " << leakCount << " leaks, " << leakSize << " bytes\n";
        m_logFile << "Stats: " << m_totalAllocated << " bytes allocated, "
            << m_totalFreed << " bytes freed, "
            << m_peakUsage << " bytes peak usage\n";
    }

    static MemoryTracker& getInstance() {
        static MemoryTracker instance;
        return instance;
    }
};

// Hook implementations

// malloc hook
void* hooked_malloc(size_t size) {
    void* ptr = original_malloc(size);
    if (ptr) {
        MemoryTracker::getInstance().trackAllocation(ptr, size);
    }
    return ptr;
}

// free hook
void hooked_free(void* ptr) {
    if (ptr) {
        MemoryTracker::getInstance().trackFree(ptr);
    }
    original_free(ptr);
}

// realloc hook
void* hooked_realloc(void* ptr, size_t size) {
    void* newPtr = original_realloc(ptr, size);
    if (newPtr) {
        MemoryTracker::getInstance().trackRealloc(ptr, newPtr, size);
    }
    return newPtr;
}

// calloc hook
void* hooked_calloc(size_t num, size_t size) {
    void* ptr = original_calloc(num, size);
    if (ptr) {
        MemoryTracker::getInstance().trackAllocation(ptr, num * size);
    }
    return ptr;
}

// strcpy hook
char* hooked_strcpy(char* dest, const char* src) {
    if (dest && src) {
        MemoryTracker::getInstance().checkStringSafety(dest, src, "strcpy");
    }
    return original_strcpy(dest, src);
}

// strncpy hook
char* hooked_strncpy(char* dest, const char* src, size_t count) {
    if (dest && src) {
        MemoryTracker::getInstance().checkBufferOverflow(dest, src, count, "strncpy");
    }
    return original_strncpy(dest, src, count);
}

// strcat hook
char* hooked_strcat(char* dest, const char* src) {
    if (dest && src) {
        // For strcat, we need to check if dest + strlen(dest) + strlen(src) + 1 exceeds buffer
        size_t destLen = strlen(dest);
        size_t srcLen = strlen(src);
        MemoryTracker::getInstance().checkBufferOverflow(
            dest, src, destLen + srcLen + 1, "strcat");
    }
    return original_strcat(dest, src);
}

// strncat hook
char* hooked_strncat(char* dest, const char* src, size_t count) {
    if (dest && src) {
        size_t destLen = strlen(dest);
        MemoryTracker::getInstance().checkBufferOverflow(
            dest, src, destLen + count + 1, "strncat");
    }
    return original_strncat(dest, src, count);
}

// memcpy hook
void* hooked_memcpy(void* dest, const void* src, size_t count) {
    if (dest && src) {
        MemoryTracker::getInstance().checkBufferOverflow(dest, src, count, "memcpy");
    }
    return original_memcpy(dest, src, count);
}

// memmove hook
void* hooked_memmove(void* dest, const void* src, size_t count) {
    if (dest && src) {
        MemoryTracker::getInstance().checkBufferOverflow(dest, src, count, "memmove");
    }
    return original_memmove(dest, src, count);
}

// memset hook
void* hooked_memset(void* dest, int ch, size_t count) {
    if (dest) {
        MemoryTracker::getInstance().checkBufferOverflow(dest, nullptr, count, "memset");
    }
    return original_memset(dest, ch, count);
}

// FunctionHooker for modular hook installation
class FunctionHooker {
private:
    ThreadPoolHook* m_hook;
    bool m_verbose;

public:
    FunctionHooker() : m_verbose(false) {
        m_hook = GetHookInstance();
    }

    void setVerbose(bool verbose) {
        m_verbose = verbose;
        MemoryTracker::getInstance().setVerbose(verbose);
    }

    void setLogFile(const std::string& logFilePath) {
        MemoryTracker::getInstance().setLogFile(logFilePath);
    }

    bool hookMemoryFunctions() {
        bool success = true;

        // Hook memory allocation functions
        success &= m_hook->hook<MallocFuncType>(
            (MallocFuncType)&malloc,
            (MallocFuncType)&hooked_malloc,
            &original_malloc);

        success &= m_hook->hook<FreeFuncType>(
            (FreeFuncType)&free,
            (FreeFuncType)&hooked_free,
            &original_free);

        success &= m_hook->hook<ReallocFuncType>(
            (ReallocFuncType)&realloc,
            (ReallocFuncType)&hooked_realloc,
            &original_realloc);

        success &= m_hook->hook<CallocFuncType>(
            (CallocFuncType)&calloc,
            (CallocFuncType)&hooked_calloc,
            &original_calloc);

        if (m_verbose) {
            std::cout << "Memory allocation functions "
                << (success ? "hooked successfully" : "hook failed") << std::endl;
        }

        return success;
    }

    bool hookStringFunctions() {
        bool success = true;

        // Hook string functions
        success &= m_hook->hook<StrcpyFuncType>(
            (StrcpyFuncType)&strcpy,
            (StrcpyFuncType)&hooked_strcpy,
            &original_strcpy);

        success &= m_hook->hook<StrncpyFuncType>(
            (StrncpyFuncType)&strncpy,
            (StrncpyFuncType)&hooked_strncpy,
            &original_strncpy);

        success &= m_hook->hook<StrcatFuncType>(
            (StrcatFuncType)&strcat,
            (StrcatFuncType)&hooked_strcat,
            &original_strcat);

        success &= m_hook->hook<StrncatFuncType>(
            (StrncatFuncType)&strncat,
            (StrncatFuncType)&hooked_strncat,
            &original_strncat);

        if (m_verbose) {
            std::cout << "String functions "
                << (success ? "hooked successfully" : "hook failed") << std::endl;
        }

        return success;
    }

    bool hookMemoryOperations() {
        bool success = true;

        // Hook memory operations
        success &= m_hook->hook<MemcpyFuncType>(
            (MemcpyFuncType)&memcpy,
            (MemcpyFuncType)&hooked_memcpy,
            &original_memcpy);

        success &= m_hook->hook<MemmoveFuncType>(
            (MemmoveFuncType)&memmove,
            (MemmoveFuncType)&hooked_memmove,
            &original_memmove);

        success &= m_hook->hook<MemsetFuncType>(
            (MemsetFuncType)&memset,
            (MemsetFuncType)&hooked_memset,
            &original_memset);

        if (m_verbose) {
            std::cout << "Memory operations "
                << (success ? "hooked successfully" : "hook failed") << std::endl;
        }

        return success;
    }

    bool hookAll() {
        bool memorySuccess = hookMemoryFunctions();
        bool stringSuccess = hookStringFunctions();
        bool operationsSuccess = hookMemoryOperations();

        return memorySuccess && stringSuccess && operationsSuccess;
    }

    void unhookAll() {
        ThreadPoolHook* hook = GetHookInstance();
        hook->unhookAll();

        if (m_verbose) {
            std::cout << "All hooks removed" << std::endl;
        }
    }

    static FunctionHooker& getInstance() {
        static FunctionHooker instance;
        return instance;
    }
};

// External API for hooking functions
extern "C" {
    __declspec(dllexport) bool SetupAllHooks(bool verbose = false) {
        FunctionHooker::getInstance().setVerbose(verbose);
        return FunctionHooker::getInstance().hookAll();
    }

    __declspec(dllexport) bool SetupMemoryHooks(bool verbose = false) {
        FunctionHooker::getInstance().setVerbose(verbose);
        return FunctionHooker::getInstance().hookMemoryFunctions();
    }

    __declspec(dllexport) bool SetupStringHooks(bool verbose = false) {
        FunctionHooker::getInstance().setVerbose(verbose);
        return FunctionHooker::getInstance().hookStringFunctions();
    }

    __declspec(dllexport) bool SetupMemoryOperationHooks(bool verbose = false) {
        FunctionHooker::getInstance().setVerbose(verbose);
        return FunctionHooker::getInstance().hookMemoryOperations();
    }

    __declspec(dllexport) void SetHookLogFile(const char* logFilePath) {
        FunctionHooker::getInstance().setLogFile(logFilePath);
    }

    __declspec(dllexport) void RemoveAllHooks() {
        FunctionHooker::getInstance().unhookAll();
    }
}