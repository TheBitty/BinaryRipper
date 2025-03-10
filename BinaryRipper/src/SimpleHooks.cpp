#define _CRT_SECURE_NO_WARNINGS
#include "includes/hook.h"
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>

// Global debug log
std::ofstream g_debug_log;

// Function to initialize debug log
void init_debug_log() {
    g_debug_log.open("hook_debug.log", std::ios::out | std::ios::trunc);
    g_debug_log << "Hook debugging started at " << GetTickCount64() << std::endl;
    g_debug_log.flush();
}

// Function to add to debug log
void debug_log(const std::string& message) {
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

// Original function pointers
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
void initialize_original_functions() {
    debug_log("Initializing original function pointers");

    // Get handles to required DLLs
    HMODULE ucrtBase = GetModuleHandleA("ucrtbase.dll");
    if (!ucrtBase) {
        debug_log("ERROR: Could not get handle to ucrtbase.dll");
        ucrtBase = LoadLibraryA("ucrtbase.dll");
        if (!ucrtBase) {
            debug_log("ERROR: Failed to load ucrtbase.dll");
            return;
        }
    }
    debug_log("Got handle to ucrtbase.dll: " + std::to_string((uintptr_t)ucrtBase));

    // Get function addresses directly from the DLL
    original_malloc = (MallocFuncType)GetProcAddress(ucrtBase, "malloc");
    if (!original_malloc) {
        debug_log("ERROR: Failed to get malloc address");
    }
    else {
        debug_log("Got malloc address: " + std::to_string((uintptr_t)original_malloc));
    }

    original_free = (FreeFuncType)GetProcAddress(ucrtBase, "free");
    if (!original_free) {
        debug_log("ERROR: Failed to get free address");
    }
    else {
        debug_log("Got free address: " + std::to_string((uintptr_t)original_free));
    }

    original_realloc = (ReallocFuncType)GetProcAddress(ucrtBase, "realloc");
    if (!original_realloc) {
        debug_log("ERROR: Failed to get realloc address");
    }
    else {
        debug_log("Got realloc address: " + std::to_string((uintptr_t)original_realloc));
    }

    original_calloc = (CallocFuncType)GetProcAddress(ucrtBase, "calloc");
    if (!original_calloc) {
        debug_log("ERROR: Failed to get calloc address");
    }
    else {
        debug_log("Got calloc address: " + std::to_string((uintptr_t)original_calloc));
    }
}

// Simplified hook implementations with debug logging
void* __cdecl hooked_malloc(size_t size) {
    debug_log("Entered hooked_malloc for size: " + std::to_string(size));

    if (in_malloc_hook) {
        debug_log("Already in malloc hook, calling original directly");
        if (!original_malloc) {
            debug_log("ERROR: original_malloc is NULL!");
            // As a fallback, try to get the function from kernel32
            return HeapAlloc(GetProcessHeap(), 0, size);
        }
        return original_malloc(size);
    }

    debug_log("Setting in_malloc_hook = true");
    in_malloc_hook = true;

    if (!original_malloc) {
        debug_log("ERROR: original_malloc is NULL in main hook!");
        in_malloc_hook = false;
        return HeapAlloc(GetProcessHeap(), 0, size);
    }

    void* ptr = original_malloc(size);
    debug_log("Called original_malloc, got ptr: " + std::to_string((uintptr_t)ptr));

    debug_log("Setting in_malloc_hook = false");
    in_malloc_hook = false;
    return ptr;
}

void __cdecl hooked_free(void* ptr) {
    debug_log("Entered hooked_free for ptr: " + std::to_string((uintptr_t)ptr));

    if (in_free_hook) {
        debug_log("Already in free hook, calling original directly");
        if (!original_free) {
            debug_log("ERROR: original_free is NULL!");
            // As a fallback, try to free using HeapFree
            HeapFree(GetProcessHeap(), 0, ptr);
            return;
        }
        original_free(ptr);
        return;
    }

    debug_log("Setting in_free_hook = true");
    in_free_hook = true;

    if (!original_free) {
        debug_log("ERROR: original_free is NULL in main hook!");
        in_free_hook = false;
        HeapFree(GetProcessHeap(), 0, ptr);
        return;
    }

    original_free(ptr);
    debug_log("Called original_free");

    debug_log("Setting in_free_hook = false");
    in_free_hook = false;
}

void* __cdecl hooked_realloc(void* ptr, size_t size) {
    debug_log("Entered hooked_realloc for ptr: " + std::to_string((uintptr_t)ptr) + ", size: " + std::to_string(size));

    if (in_realloc_hook) {
        debug_log("Already in realloc hook, calling original directly");
        if (!original_realloc) {
            debug_log("ERROR: original_realloc is NULL!");
            return NULL;
        }
        return original_realloc(ptr, size);
    }

    debug_log("Setting in_realloc_hook = true");
    in_realloc_hook = true;

    if (!original_realloc) {
        debug_log("ERROR: original_realloc is NULL in main hook!");
        in_realloc_hook = false;
        return NULL;
    }

    void* newPtr = original_realloc(ptr, size);
    debug_log("Called original_realloc, got ptr: " + std::to_string((uintptr_t)newPtr));

    debug_log("Setting in_realloc_hook = false");
    in_realloc_hook = false;
    return newPtr;
}

void* __cdecl hooked_calloc(size_t num, size_t size) {
    debug_log("Entered hooked_calloc for num: " + std::to_string(num) + ", size: " + std::to_string(size));

    if (in_calloc_hook) {
        debug_log("Already in calloc hook, calling original directly");
        if (!original_calloc) {
            debug_log("ERROR: original_calloc is NULL!");
            return NULL;
        }
        return original_calloc(num, size);
    }

    debug_log("Setting in_calloc_hook = true");
    in_calloc_hook = true;

    if (!original_calloc) {
        debug_log("ERROR: original_calloc is NULL in main hook!");
        in_calloc_hook = false;
        return NULL;
    }

    void* ptr = original_calloc(num, size);
    debug_log("Called original_calloc, got ptr: " + std::to_string((uintptr_t)ptr));

    debug_log("Setting in_calloc_hook = false");
    in_calloc_hook = false;
    return ptr;
}

// Debug wrapper for GetHookInstance
ThreadPoolHook* DebugGetHookInstance() {
    debug_log("Getting hook instance");
    ThreadPoolHook* instance = ThreadPoolHook::getInstance();
    debug_log("Got hook instance: " + std::to_string((uintptr_t)instance));
    return instance;
}

// FunctionHooker for hook installation
class FunctionHooker {
private:
    ThreadPoolHook* m_hook;
    bool m_verbose;

public:
    FunctionHooker() : m_verbose(false) {
        debug_log("Creating FunctionHooker");
        m_hook = DebugGetHookInstance();
        debug_log("FunctionHooker created, hook instance: " + std::to_string((uintptr_t)m_hook));
    }

    void setVerbose(bool verbose) {
        debug_log("Setting verbose: " + std::to_string(verbose));
        m_verbose = verbose;
    }

    bool hookMemoryFunctions() {
        debug_log("Hooking memory functions");
        bool success = true;

        // Initialize original functions if needed
        if (!original_malloc || !original_free || !original_realloc || !original_calloc) {
            debug_log("Initializing original functions");
            initialize_original_functions();
        }

        // Hook malloc with delay
        debug_log("Hooking malloc");
        success &= m_hook->hook(
            (MallocFuncType)&malloc,
            (MallocFuncType)&hooked_malloc,
            &original_malloc);
        debug_log("Malloc hook result: " + std::to_string(success));
        debug_log("Sleeping after malloc hook");
        Sleep(100);

        // Hook free with delay
        debug_log("Hooking free");
        success &= m_hook->hook(
            (FreeFuncType)&free,
            (FreeFuncType)&hooked_free,
            &original_free);
        debug_log("Free hook result: " + std::to_string(success));
        debug_log("Sleeping after free hook");
        Sleep(100);

        // Hook realloc with delay
        debug_log("Hooking realloc");
        success &= m_hook->hook(
            (ReallocFuncType)&realloc,
            (ReallocFuncType)&hooked_realloc,
            &original_realloc);
        debug_log("Realloc hook result: " + std::to_string(success));
        debug_log("Sleeping after realloc hook");
        Sleep(100);

        // Hook calloc with delay
        debug_log("Hooking calloc");
        success &= m_hook->hook(
            (CallocFuncType)&calloc,
            (CallocFuncType)&hooked_calloc,
            &original_calloc);
        debug_log("Calloc hook result: " + std::to_string(success));
        debug_log("Sleeping after calloc hook");
        Sleep(100);

        if (m_verbose) {
            std::cout << "Memory allocation functions "
                << (success ? "hooked successfully" : "hook failed") << std::endl;
        }

        debug_log("Memory functions hooked: " + std::to_string(success));
        return success;
    }

    void unhookAll() {
        debug_log("Unhooking all functions");
        ThreadPoolHook* hook = DebugGetHookInstance();
        hook->unhookAll();
        debug_log("All functions unhooked");

        if (m_verbose) {
            std::cout << "All hooks removed" << std::endl;
        }
    }

    static FunctionHooker& getInstance() {
        debug_log("Getting FunctionHooker instance");
        static FunctionHooker instance;
        debug_log("Returning FunctionHooker instance");
        return instance;
    }
};

// External API for hooking functions
extern "C" {
    __declspec(dllexport) bool SetupAllHooks(bool verbose = false) {
        // Initialize debug log first
        init_debug_log();
        debug_log("SetupAllHooks called with verbose: " + std::to_string(verbose));

        FunctionHooker::getInstance().setVerbose(verbose);
        bool result = FunctionHooker::getInstance().hookMemoryFunctions();
        debug_log("SetupAllHooks returning: " + std::to_string(result));
        return result;
    }

    __declspec(dllexport) bool SetupMemoryHooks(bool verbose = false) {
        debug_log("SetupMemoryHooks called with verbose: " + std::to_string(verbose));

        FunctionHooker::getInstance().setVerbose(verbose);
        bool result = FunctionHooker::getInstance().hookMemoryFunctions();
        debug_log("SetupMemoryHooks returning: " + std::to_string(result));
        return result;
    }

    __declspec(dllexport) void SetHookLogFile(const char* logFilePath) {
        debug_log("SetHookLogFile called with path: " + std::string(logFilePath ? logFilePath : "NULL"));
        // Do nothing for now
    }

    __declspec(dllexport) void RemoveAllHooks() {
        debug_log("RemoveAllHooks called");
        FunctionHooker::getInstance().unhookAll();
        debug_log("RemoveAllHooks completed");

        // Close debug log
        if (g_debug_log.is_open()) {
            g_debug_log << "Closing log" << std::endl;
            g_debug_log.close();
        }
    }
}