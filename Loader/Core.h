#pragma once
#include "Native.h"

namespace Fog::Core {

    // --- Магические хеши (Константы времени компиляции, 0 оверхеда) ---
    constexpr DWORD HASH_NtOpenProcess = 0x3F4DD136;
    constexpr DWORD HASH_NtReadVirtualMemory = 0x307C3661;
    constexpr DWORD HASH_NtWriteVirtualMemory = 0xFAE162D0;
    constexpr DWORD HASH_NtAllocateVirtualMemory = 0xC86105CA;
    constexpr DWORD HASH_NtFreeVirtualMemory = 0xB5567B67;
    constexpr DWORD HASH_NtProtectVirtualMemory = 0xA4D0D586;
    constexpr DWORD HASH_NtDuplicateObject = 0x781AA9F7;

    constexpr DWORD HASH_NtQuerySystemInformation = 0x684921E6;
    constexpr DWORD HASH_NtQueryInformationProcess = 0x0A405E60;

    constexpr DWORD HASH_NtQueueApcThread = 0x598bfe76;
    constexpr DWORD HASH_NtGetContextThread = 0x1c15fe02;
    constexpr DWORD HASH_NtSetContextThread = 0xae93c48e;
    constexpr DWORD HASH_NtResumeThread = 0xc771e1ce;
    constexpr DWORD HASH_NtSuspendThread = 0xf62771bf;

    constexpr DWORD HASH_NtQueryVirtualMemory = 0x488b499b;
    constexpr DWORD HASH_NtMapViewOfSection = 0x8557a148;
    constexpr DWORD HASH_NtFlushInstructionCache = 0x3347055d;

    constexpr DWORD HASH_NtClose = 0x3ccc557b;

    // Должны совпадать с Fog::Core::HashString("RtlAddVectoredExceptionHandler") и т.д.
    constexpr DWORD HASH_RtlAddVectoredExceptionHandler = 0x1cb8a887;
    constexpr DWORD HASH_RtlRemoveVectoredExceptionHandler = 0xa7c9312c;

    // Специфичные цели
    constexpr DWORD HASH_AMSI_SCAN_BUFFER = 0x27D9EE2C;
    constexpr DWORD HASH_LDR_LOAD_DLL = 0x4EE660C1;
    constexpr DWORD HASH_ETW_EVENT_WRITE = 0x4CA9D500;

    // --- Функции ядра ---
    DWORD HashString(const char* word);
    uintptr_t GetModuleBase(const wchar_t* moduleName);
    uintptr_t GetExportAddress(uintptr_t moduleBase, DWORD targetHash);
    DWORD GetModuleSize(uintptr_t moduleBase);
    DWORD ExtractSSN(uintptr_t moduleBase, uintptr_t address);
    bool Initialize();
}

// Typedef для функции инициализации ядра
typedef void (*InitializeCore_t)(SYSCALL_BRIDGE*, HANDLE);