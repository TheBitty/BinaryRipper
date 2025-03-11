#define _CRT_SECURE_NO_WARNINGS
#include "includes/hook.h"
#include <Windows.h>

// ----- Log System: Using direct Windows API to avoid allocations -----
HANDLE g_log_file = INVALID_HANDLE_VALUE;
char g_log_buffer[512]; // Static buffer for log messages

// Safe minimal logging with no memory allocations
void safe_log(const char* message) {
    if (g_log_file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        DWORD time = GetTickCount();

        // Format timestamp
        int len = sprintf_s(g_log_buffer, "[%u] %s\r\n", time, message);

        // Write directly to file handle
        WriteFile(g_log_file, g_log_buffer, len, &written, NULL);
    }
}

// ----- Function Types and Original Pointers -----
typedef void* (__cdecl* MallocFuncType)(size_t);
typedef void(__cdecl* FreeFuncType)(void*);
typedef void* (__cdecl* ReallocFuncType)(void*, size_t);
typedef void* (__cdecl* CallocFuncType)(size_t, size_t);

// Original function pointers
static MallocFuncType original_malloc = NULL;
static FreeFuncType original_free = NULL;
static ReallocFuncType original_realloc = NULL;
static CallocFuncType original_calloc = NULL;

// ----- Recursion Prevention: Using per-thread depth counters -----
thread_local int malloc_depth = 0;
thread_local int free_depth = 0;
thread_local int realloc_depth = 0;
thread_local int calloc_depth = 0;

// ----- Hook Functions: Ultra minimal implementations -----

void* __cdecl hooked_malloc(size_t size) {
    // Recursion guard - use counter instead of boolean
    malloc_depth++;

    // Always go straight to original for nested calls
    if (malloc_depth > 1) {
        void* result = original_malloc ? original_malloc(size) :
            HeapAlloc(GetProcessHeap(), 0, size);
        malloc_depth--;
        return result;
    }

    // First get the result
    void* ptr = original_malloc ? original_malloc(size) :
        HeapAlloc(GetProcessHeap(), 0, size);

    // Then log with minimal operations
    if (ptr && g_log_file != INVALID_HANDLE_VALUE) {
        sprintf_s(g_log_buffer, "malloc(%zu) = %p", size, ptr);
        safe_log(g_log_buffer);
    }

    malloc_depth--;
    return ptr;
}

void __cdecl hooked_free(void* ptr) {
    // Skip null pointers
    if (!ptr) {
        if (original_free) original_free(ptr);
        return;
    }

    // Recursion guard
    free_depth++;

    // Always go straight to original for nested calls
    if (free_depth > 1) {
        if (original_free)
            original_free(ptr);
        else
            HeapFree(GetProcessHeap(), 0, ptr);
        free_depth--;
        return;
    }

    // Log first, then free
    sprintf_s(g_log_buffer, "free(%p)", ptr);
    safe_log(g_log_buffer);

    // Perform the free
    if (original_free)
        original_free(ptr);
    else
        HeapFree(GetProcessHeap(), 0, ptr);

    free_depth--;
}

void* __cdecl hooked_realloc(void* ptr, size_t size) {
    // Recursion guard
    realloc_depth++;

    // Always go straight to original for nested calls
    if (realloc_depth > 1) {
        void* result = original_realloc ? original_realloc(ptr, size) : NULL;
        realloc_depth--;
        return result;
    }

    // First get the result
    void* newptr = original_realloc ? original_realloc(ptr, size) : NULL;

    // Log with minimal operations
    if (g_log_file != INVALID_HANDLE_VALUE) {
        sprintf_s(g_log_buffer, "realloc(%p, %zu) = %p", ptr, size, newptr);
        safe_log(g_log_buffer);
    }

    realloc_depth--;
    return newptr;
}

void* __cdecl hooked_calloc(size_t count, size_t size) {
    // Recursion guard
    calloc_depth++;

    // Always go straight to original for nested calls
    if (calloc_depth > 1) {
        void* result = original_calloc ? original_calloc(count, size) : NULL;
        calloc_depth--;
        return result;
    }

    // First get the result
    void* ptr = original_calloc ? original_calloc(count, size) : NULL;

    // Log with minimal operations
    if (ptr && g_log_file != INVALID_HANDLE_VALUE) {
        sprintf_s(g_log_buffer, "calloc(%zu, %zu) = %p", count, size, ptr);
        safe_log(g_log_buffer);
    }

    calloc_depth--;
    return ptr;
}

// ----- Function to get CRT pointers -----
BOOL initialize_crt_functions() {
    // Try multiple possible CRT DLLs
    const char* potential_dlls[] = { "ucrtbase.dll", "msvcrt.dll", "api-ms-win-crt-heap-l1-1-0.dll" };
    HMODULE crt_handle = NULL;

    for (int i = 0; i < 3; i++) {
        crt_handle = GetModuleHandleA(potential_dlls[i]);
        if (crt_handle) {
            sprintf_s(g_log_buffer, "Found CRT in: %s", potential_dlls[i]);
            safe_log(g_log_buffer);
            break;
        }
    }

    // If not found, try loading explicitly
    if (!crt_handle) {
        crt_handle = LoadLibraryA("ucrtbase.dll");
    }

    // Still no CRT handle
    if (!crt_handle) {
        safe_log("ERROR: Failed to find CRT library");
        return FALSE;
    }

    // Get function addresses
    original_malloc = (MallocFuncType)GetProcAddress(crt_handle, "malloc");
    original_free = (FreeFuncType)GetProcAddress(crt_handle, "free");
    original_realloc = (ReallocFuncType)GetProcAddress(crt_handle, "realloc");
    original_calloc = (CallocFuncType)GetProcAddress(crt_handle, "calloc");

    // Check if we got all functions
    if (!original_malloc || !original_free || !original_realloc || !original_calloc) {
        sprintf_s(g_log_buffer, "Error: Failed to get all functions. malloc=%p, free=%p",
            original_malloc, original_free);
        safe_log(g_log_buffer);
        return FALSE;
    }

    safe_log("Successfully initialized all CRT functions");
    return TRUE;
}

// ----- Hook Manager Class -----
class SimpleHookManager {
private:
    ThreadPoolHook* m_hook;
    BOOL m_initialized;
    BOOL m_verbose;

public:
    SimpleHookManager() : m_hook(NULL), m_initialized(FALSE), m_verbose(FALSE) {
        // Initialize log
        g_log_file = CreateFileA("hook_log.txt", GENERIC_WRITE, FILE_SHARE_READ,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        if (g_log_file != INVALID_HANDLE_VALUE) {
            safe_log("SimpleHookManager created");
        }

        // Get hook instance 
        m_hook = ThreadPoolHook::getInstance();
    }

    ~SimpleHookManager() {
        // Clean up
        if (g_log_file != INVALID_HANDLE_VALUE) {
            CloseHandle(g_log_file);
            g_log_file = INVALID_HANDLE_VALUE;
        }
    }

    void setVerbose(BOOL verbose) {
        m_verbose = verbose;
    }

    BOOL setupHooks() {
        safe_log("Setting up memory hooks");

        // Initialize CRT functions if needed
        if (!m_initialized) {
            if (!initialize_crt_functions()) {
                safe_log("Failed to initialize CRT functions");
                return FALSE;
            }
            m_initialized = TRUE;
        }

        // Install hooks one by one with error checking
        BOOL success = TRUE;

        // Hook malloc
        if (!m_hook->hook(original_malloc, hooked_malloc, &original_malloc)) {
            safe_log("Failed to hook malloc");
            success = FALSE;
        }

        // Hook free
        if (!m_hook->hook(original_free, hooked_free, &original_free)) {
            safe_log("Failed to hook free");
            success = FALSE;
        }

        // Hook realloc
        if (!m_hook->hook(original_realloc, hooked_realloc, &original_realloc)) {
            safe_log("Failed to hook realloc");
            success = FALSE;
        }

        // Hook calloc
        if (!m_hook->hook(original_calloc, hooked_calloc, &original_calloc)) {
            safe_log("Failed to hook calloc");
            success = FALSE;
        }

        if (success) {
            safe_log("All memory hooks installed successfully");
        }
        else {
            safe_log("One or more hooks failed");
        }

        if (m_verbose) {
            // Use direct Windows API to avoid potential issues with cout
            const char* message = success ?
                "Memory allocation functions hooked successfully\r\n" :
                "Memory allocation functions hook failed\r\n";
            DWORD written;
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, lstrlenA(message), &written, NULL);
        }

        return success;
    }

    void removeHooks() {
        safe_log("Removing all hooks");
        if (m_hook) {
            m_hook->unhookAll();
        }
        safe_log("All hooks removed");

        if (m_verbose) {
            // Use direct Windows API to avoid potential issues with cout
            const char* message = "All hooks removed\r\n";
            DWORD written;
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, lstrlenA(message), &written, NULL);
        }
    }

    void setLogFile(const char* logPath) {
        // Close existing log file
        if (g_log_file != INVALID_HANDLE_VALUE) {
            CloseHandle(g_log_file);
            g_log_file = INVALID_HANDLE_VALUE;
        }

        // Open new log file if path provided
        if (logPath) {
            g_log_file = CreateFileA(logPath, GENERIC_WRITE, FILE_SHARE_READ,
                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (g_log_file != INVALID_HANDLE_VALUE) {
                sprintf_s(g_log_buffer, "Log file set to: %s", logPath);
                safe_log(g_log_buffer);
            }
        }
    }

    // Singleton instance
    static SimpleHookManager& getInstance() {
        static SimpleHookManager instance;
        return instance;
    }
};

// ----- Public API Functions -----
extern "C" {
    __declspec(dllexport) bool SetupAllHooks(bool verbose) {
        SimpleHookManager::getInstance().setVerbose(verbose);
        return SimpleHookManager::getInstance().setupHooks();
    }

    __declspec(dllexport) bool SetupMemoryHooks(bool verbose) {
        SimpleHookManager::getInstance().setVerbose(verbose);
        return SimpleHookManager::getInstance().setupHooks();
    }

    __declspec(dllexport) void SetHookLogFile(const char* logFilePath) {
        SimpleHookManager::getInstance().setLogFile(logFilePath);
    }

    __declspec(dllexport) void RemoveAllHooks() {
        SimpleHookManager::getInstance().removeHooks();
    }
}