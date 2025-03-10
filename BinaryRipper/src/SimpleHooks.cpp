#define _CRT_SECURE_NO_WARNINGS
#include "includes/hook.h"
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>

// Global debug log with direct buffer to avoid memory allocations
std::ofstream g_debug_log;
char g_log_buffer[1024];

// Function to initialize debug log
void init_debug_log() {
    g_debug_log.open("hook_debug.log", std::ios::out | std::ios::trunc);
    g_debug_log << "Hook debugging started at " << GetTickCount64() << std::endl;
    g_debug_log.flush();
}

// Safe logging function that avoids memory allocations
void debug_log_safe(const char* message) {
    if (g_debug_log.is_open()) {
        g_debug_log << "[" << GetTickCount64() << "] " << message << std::endl;
        g_debug_log.flush();
    }
}

// Function type definitions
typedef void* (__cdecl* MallocFuncType)(size_t);
typedef void(__cdecl* FreeFuncType)(void*);
typedef void* (__cdecl* ReallocFuncType)(void*, size_t);
typedef void* (__cdecl* CallocFuncType)(size_t, size_t);

// Original function pointers - initialized before hooking
MallocFuncType original_malloc = nullptr;
FreeFuncType original_free = nullptr;
ReallocFuncType original_realloc = nullptr;
CallocFuncType original_calloc = nullptr;

// Thread-local flags for recursion prevention
thread_local bool in_malloc_hook = false;
thread_local bool in_free_hook = false;
thread_local bool in_realloc_hook = false;
thread_local bool in_calloc_hook = false;

// Get direct pointers to C runtime functions
bool initialize_original_functions() {
    debug_log_safe("Initializing original function pointers");

    // Get handles to required DLLs - we'll try multiple potential DLLs
    const char* potential_dlls[] = { "ucrtbase.dll", "msvcrt.dll", "libucrt.dll" };
    HMODULE crtHandle = nullptr;

    for (const char* dllName : potential_dlls) {
        crtHandle = GetModuleHandleA(dllName);
        if (crtHandle) {
            sprintf_s(g_log_buffer, "Found CRT in: %s", dllName);
            debug_log_safe(g_log_buffer);
            break;
        }
    }

    if (!crtHandle) {
        debug_log_safe("ERROR: Could not find CRT DLL, trying to load ucrtbase.dll explicitly");
        crtHandle = LoadLibraryA("ucrtbase.dll");
        if (!crtHandle) {
            debug_log_safe("CRITICAL ERROR: Failed to load any CRT DLL");
            return false;
        }
    }

    // Save original function pointers
    original_malloc = (MallocFuncType)GetProcAddress(crtHandle, "malloc");
    original_free = (FreeFuncType)GetProcAddress(crtHandle, "free");
    original_realloc = (ReallocFuncType)GetProcAddress(crtHandle, "realloc");
    original_calloc = (CallocFuncType)GetProcAddress(crtHandle, "calloc");

    // Validate all function pointers
    bool success = (original_malloc != nullptr && original_free != nullptr &&
        original_realloc != nullptr && original_calloc != nullptr);

    if (!success) {
        debug_log_safe("ERROR: Failed to get one or more function addresses");
        return false;
    }

    debug_log_safe("Successfully initialized all CRT function pointers");
    return true;
}

// Hooked function implementations - simplified to avoid recursion issues
void* __cdecl hooked_malloc(size_t size) {
    // Check for recursion
    if (in_malloc_hook) {
        return original_malloc(size); // Direct call with no logging to avoid recursion
    }

    in_malloc_hook = true;
    void* ptr = original_malloc(size);

    // Only use safe logging that doesn't allocate memory
    sprintf_s(g_log_buffer, "malloc(%zu) = %p", size, ptr);
    debug_log_safe(g_log_buffer);

    in_malloc_hook = false;
    return ptr;
}

void __cdecl hooked_free(void* ptr) {
    if (in_free_hook) {
        original_free(ptr);
        return;
    }

    in_free_hook = true;

    sprintf_s(g_log_buffer, "free(%p)", ptr);
    debug_log_safe(g_log_buffer);

    original_free(ptr);
    in_free_hook = false;
}

void* __cdecl hooked_realloc(void* ptr, size_t size) {
    if (in_realloc_hook) {
        return original_realloc(ptr, size);
    }

    in_realloc_hook = true;
    void* newPtr = original_realloc(ptr, size);

    sprintf_s(g_log_buffer, "realloc(%p, %zu) = %p", ptr, size, newPtr);
    debug_log_safe(g_log_buffer);

    in_realloc_hook = false;
    return newPtr;
}

void* __cdecl hooked_calloc(size_t num, size_t size) {
    if (in_calloc_hook) {
        return original_calloc(num, size);
    }

    in_calloc_hook = true;
    void* ptr = original_calloc(num, size);

    sprintf_s(g_log_buffer, "calloc(%zu, %zu) = %p", num, size, ptr);
    debug_log_safe(g_log_buffer);

    in_calloc_hook = false;
    return ptr;
}

// FunctionHooker for hook installation
class FunctionHooker {
private:
    ThreadPoolHook* m_hook;
    bool m_verbose;
    bool m_initialized;

public:
    FunctionHooker() : m_verbose(false), m_initialized(false) {
        debug_log_safe("Creating FunctionHooker");
        m_hook = ThreadPoolHook::getInstance();
        debug_log_safe("FunctionHooker created");
    }

    void setVerbose(bool verbose) {
        m_verbose = verbose;
    }

    bool hookMemoryFunctions() {
        debug_log_safe("Hooking memory functions");

        // Initialize function pointers first, before any hooking
        if (!m_initialized) {
            if (!initialize_original_functions()) {
                debug_log_safe("Failed to initialize original function pointers");
                return false;
            }
            m_initialized = true;
        }

        // Hook all functions at once to minimize vulnerability window
        bool success = true;

        // We'll install all hooks before checking results to ensure atomicity
        bool malloc_result = m_hook->hook(original_malloc, hooked_malloc, &original_malloc);
        bool free_result = m_hook->hook(original_free, hooked_free, &original_free);
        bool realloc_result = m_hook->hook(original_realloc, hooked_realloc, &original_realloc);
        bool calloc_result = m_hook->hook(original_calloc, hooked_calloc, &original_calloc);

        // Log each result separately
        sprintf_s(g_log_buffer, "Hook results - malloc: %d, free: %d, realloc: %d, calloc: %d",
            malloc_result, free_result, realloc_result, calloc_result);
        debug_log_safe(g_log_buffer);

        success = malloc_result && free_result && realloc_result && calloc_result;

        if (m_verbose) {
            std::cout << "Memory allocation functions "
                << (success ? "hooked successfully" : "hook failed") << std::endl;
        }

        return success;
    }

    void unhookAll() {
        debug_log_safe("Unhooking all functions");
        m_hook->unhookAll();
        debug_log_safe("All functions unhooked");

        if (m_verbose) {
            std::cout << "All hooks removed" << std::endl;
        }
    }

    static FunctionHooker& getInstance() {
        static FunctionHooker instance;
        return instance;
    }
};

// External API
extern "C" {
    __declspec(dllexport) bool SetupAllHooks(bool verbose) {
        // Initialize debug log first
        init_debug_log();
        debug_log_safe("SetupAllHooks called");

        FunctionHooker::getInstance().setVerbose(verbose);
        bool result = FunctionHooker::getInstance().hookMemoryFunctions();

        sprintf_s(g_log_buffer, "SetupAllHooks returning: %d", result);
        debug_log_safe(g_log_buffer);
        return result;
    }

    __declspec(dllexport) bool SetupMemoryHooks(bool verbose) {
        debug_log_safe("SetupMemoryHooks called");

        FunctionHooker::getInstance().setVerbose(verbose);
        bool result = FunctionHooker::getInstance().hookMemoryFunctions();

        sprintf_s(g_log_buffer, "SetupMemoryHooks returning: %d", result);
        debug_log_safe(g_log_buffer);
        return result;
    }

    __declspec(dllexport) void SetHookLogFile(const char* logFilePath) {
        if (logFilePath) {
            // Close existing log if open
            if (g_debug_log.is_open()) {
                g_debug_log.close();
            }

            // Open new log file
            g_debug_log.open(logFilePath, std::ios::out | std::ios::trunc);
            sprintf_s(g_log_buffer, "Logging redirected to: %s", logFilePath);
            debug_log_safe(g_log_buffer);
        }
    }

    __declspec(dllexport) void RemoveAllHooks() {
        debug_log_safe("RemoveAllHooks called");
        FunctionHooker::getInstance().unhookAll();
        debug_log_safe("RemoveAllHooks completed");

        // Close debug log
        if (g_debug_log.is_open()) {
            g_debug_log << "Closing log" << std::endl;
            g_debug_log.close();
        }
    }
}