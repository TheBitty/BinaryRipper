#pragma once
#include <Windows.h>
#include <threadpoolapiset.h>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <functional>

class ThreadPoolHook {
private:
    // Windows thread pool environment
    PTP_POOL m_pool;
    TP_CALLBACK_ENVIRON m_callbackEnv;
    PTP_CLEANUP_GROUP m_cleanupGroup;

    // Hook storage and synchronization
    std::unordered_map<void*, std::pair<void*, void*>> m_hooks; // target -> (original, hook)
    std::mutex m_hooksMutex; // Protects access to shared resources

    // Singleton instance
    static ThreadPoolHook* s_instance;

    // Private constructor for singleton pattern
    ThreadPoolHook() {
        // Initialize thread pool
        m_pool = CreateThreadpool(nullptr);
        if (!m_pool) {
            throw std::runtime_error("Failed to create thread pool");
        }

        // Configure pool size
        SetThreadpoolThreadMaximum(m_pool, 8);
        SetThreadpoolThreadMinimum(m_pool, 1);

        // Initialize callback environment
        InitializeThreadpoolEnvironment(&m_callbackEnv);
        SetThreadpoolCallbackPool(&m_callbackEnv, m_pool);

        // Create cleanup group
        m_cleanupGroup = CreateThreadpoolCleanupGroup();
        if (m_cleanupGroup) {
            SetThreadpoolCallbackCleanupGroup(&m_callbackEnv, m_cleanupGroup, nullptr);
        }
    }

public:
    // Destructor cleans up thread pool resources
    ~ThreadPoolHook() {
        if (m_cleanupGroup) {
            CloseThreadpoolCleanupGroupMembers(m_cleanupGroup, FALSE, NULL);
            CloseThreadpoolCleanupGroup(m_cleanupGroup);
        }

        if (m_pool) {
            CloseThreadpool(m_pool);
        }

        unhookAll();

        DestroyThreadpoolEnvironment(&m_callbackEnv);
    }

    // Get singleton instance
    static ThreadPoolHook* getInstance() {
        if (!s_instance) {
            s_instance = new ThreadPoolHook();
        }
        return s_instance;
    }

    // Get original function pointer
    template<typename T>
    T getOriginal(T* hooked) {
        std::lock_guard<std::mutex> lock(m_hooksMutex);
        auto it = m_hooks.find(hooked);
        if (it != m_hooks.end()) {
            return static_cast<T>(it->second.first);
        }
        return nullptr;
    }

    // Static cleanup function to release the singleton
    static void cleanup() {
        if (s_instance) {
            delete s_instance;
            s_instance = nullptr;
        }
    }

    // Install a detour hook
    template<typename T>
    bool hook(T* target, T* detour, T** original) {
        std::lock_guard<std::mutex> lock(m_hooksMutex);

        if (!target || !detour || !original) {
            return false;
        }

        // Check if hook already exists
        if (m_hooks.find(target) != m_hooks.end()) {
            return false;
        }

        // For function pointers, we need a fixed size for the hook
        const size_t hookSize =
#ifdef _M_X64
            14; // Size of indirect jump on x64
#else
            5;  // Size of direct jump on x86
#endif

        // Memory protection
        DWORD oldProtect;
        if (!VirtualProtect(target, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }

        // Store original bytes - we need to allocate memory for this
        BYTE* originalBytes = new BYTE[hookSize];
        memcpy(originalBytes, target, hookSize);
        *original = target; // Still set the original pointer

        // Create the hook - implementation depends on architecture
#ifdef _M_X64
    // 64-bit hook using indirect jump
        uint8_t* hookBytes = (uint8_t*)target;
        // JMP [RIP+0]
        hookBytes[0] = 0xFF;
        hookBytes[1] = 0x25;
        hookBytes[2] = 0x00;
        hookBytes[3] = 0x00;
        hookBytes[4] = 0x00;
        hookBytes[5] = 0x00;
        *(uintptr_t*)(&hookBytes[6]) = (uintptr_t)detour;
#else
    // 32-bit hook using direct jump
        uint8_t* hookBytes = (uint8_t*)target;
        // JMP rel32
        hookBytes[0] = 0xE9;
        *(int32_t*)(&hookBytes[1]) = (int32_t)((uintptr_t)detour - (uintptr_t)target - 5);
#endif

        // Restore protection
        VirtualProtect(target, hookSize, oldProtect, &oldProtect);

        // Flush instruction cache to ensure hook is visible
        FlushInstructionCache(GetCurrentProcess(), target, hookSize);

        // Store hook information - store the original bytes instead of the pointer
        m_hooks[target] = std::make_pair(originalBytes, detour);

        return true;
    }

    // Remove a specific hook
    template<typename T>
    bool unhook(T* target) {
        std::lock_guard<std::mutex> lock(m_hooksMutex);

        auto it = m_hooks.find(target);
        if (it == m_hooks.end()) {
            return false;
        }

        // For function pointers, we need a fixed size
        const size_t hookSize =
#ifdef _M_X64
            14; // Size of indirect jump on x64
#else
            5;  // Size of direct jump on x86
#endif

        // Get original bytes pointer
        BYTE* originalBytes = (BYTE*)(it->second.first);

        // Memory protection
        DWORD oldProtect;
        if (!VirtualProtect(target, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }

        // Restore original bytes
        memcpy(target, originalBytes, hookSize);

        // Restore protection
        VirtualProtect(target, hookSize, oldProtect, &oldProtect);

        // Flush instruction cache to ensure changes are visible
        FlushInstructionCache(GetCurrentProcess(), target, hookSize);

        // Free the memory for original bytes
        delete[] originalBytes;

        // Remove from hook map
        m_hooks.erase(it);

        return true;
    }

    // Remove all hooks
    void unhookAll() {
        std::lock_guard<std::mutex> lock(m_hooksMutex);

        for (auto& hook : m_hooks) {
            void* target = hook.first;
            BYTE* originalBytes = (BYTE*)(hook.second.first);

            // For function pointers, use a fixed size
            const size_t hookSize =
#ifdef _M_X64
                14; // Size of indirect jump on x64
#else
                5;  // Size of direct jump on x86
#endif

            // Memory protection
            DWORD oldProtect;
            if (VirtualProtect(target, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                // Restore original bytes
                memcpy(target, originalBytes, hookSize);

                // Restore protection
                VirtualProtect(target, hookSize, oldProtect, &oldProtect);

                // Flush instruction cache
                FlushInstructionCache(GetCurrentProcess(), target, hookSize);

                // Free the memory
                delete[] originalBytes;
            }
        }

        m_hooks.clear();
    }

    // Submit work to thread pool (for hook callbacks)
    template<typename Func, typename... Args>
    void submitCallback(Func&& func, Args&&... args) {
        if (!m_pool) return;

        // Create a new work item with the function and its arguments
        auto task = std::bind(std::forward<Func>(func), std::forward<Args>(args)...);

        // Allocate memory for the task (will be freed in the callback wrapper)
        auto taskPtr = new decltype(task)(std::move(task));

        // Submit the work item to the thread pool
        SubmitThreadpoolWork(CreateThreadpoolWork(
            [](PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_WORK work) {
                // Execute the task
                auto taskPtr = static_cast<decltype(task)*>(context);
                (*taskPtr)();

                // Clean up
                delete taskPtr;
                CloseThreadpoolWork(work);
            },
            taskPtr,
            &m_callbackEnv
        ));
    }
};

// Initialize static instance
ThreadPoolHook* ThreadPoolHook::s_instance = nullptr;

// Helper function to get the hook instance
inline ThreadPoolHook* GetHookInstance() {
    return ThreadPoolHook::getInstance();
}