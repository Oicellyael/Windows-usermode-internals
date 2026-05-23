#pragma once
#include <windows.h>
#include <cstdint>

// ==================== TYPES ====================
typedef LONG NTSTATUS;

// ==================== STRUCTURES ====================
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// ==================== ENUMERATIONS ====================
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5,
    SystemHandleInformation = 16,
    SystemExtendedHandleInformation = 64,
} SYSTEM_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
    MemoryWorkingSetInformation = 1,
    MemoryMappedFilenameInformation = 2,
    MemoryRegionInformation = 3,
    MemoryWorkingSetExInformation = 4
} MEMORY_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

// ==================== FUNCTION POINTERS ====================
typedef NTSTATUS(NTAPI* LdrLoadDll)(
    PWSTR           SearchPath,
    PULONG          DllCharacteristics,
    PUNICODE_STRING DllName,
    PHANDLE         DllHandle
    );

typedef VOID(NTAPI* PPS_APC_ROUTINE)(
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

// ntdll exports (not syscalls): bridge passes raw addresses for native calls from managed code.
typedef PVOID(NTAPI* PFN_RtlAddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef ULONG(NTAPI* PFN_RtlRemoveVectoredExceptionHandler)(PVOID Handle);

// ==================== EXTERNAL ASM VARIABLES ====================
extern "C" {
    // Syscall Infrastructure
    extern uintptr_t IndirectSyscallJumpAddress;

    // Memory Operations
    extern uintptr_t SsnNtAllocateVirtualMemory;
    extern uintptr_t SsnNtFreeVirtualMemory;
    extern uintptr_t SsnNtProtectVirtualMemory;
    extern uintptr_t SsnNtReadVirtualMemory;
    extern uintptr_t SsnNtWriteVirtualMemory;
    extern uintptr_t SsnNtQueryVirtualMemory;
    extern uintptr_t SsnNtMapViewOfSection;
    extern uintptr_t SsnNtFlushInstructionCache;

    // Process Operations
    extern uintptr_t SsnNtOpenProcess;
    extern uintptr_t SsnNtDuplicateObject;
    extern uintptr_t SsnNtQueryInformationProcess;
    extern uintptr_t SsnNtQuerySystemInformation;

    // Thread Operations
    extern uintptr_t SsnNtQueueApcThread;
    extern uintptr_t SsnNtGetContextThread;
    extern uintptr_t SsnNtSetContextThread;
    extern uintptr_t SsnNtResumeThread;
    extern uintptr_t SsnNtSuspendThread;

    // Utility Functions
    uintptr_t GetMyPeb();
    extern uintptr_t ntdllBase;

    // Resolved in Fog::Core::Initialize — real ntdll entry points (do not use indirect syscall stubs).
    extern uintptr_t RtlAddVectoredExceptionHandlerAddr;
    extern uintptr_t RtlRemoveVectoredExceptionHandlerAddr;
}

struct SYSCALL_BRIDGE {
    // Память
    uintptr_t NtAllocateVirtualMemory;
    uintptr_t NtFreeVirtualMemory;
    uintptr_t NtProtectVirtualMemory;
    uintptr_t NtReadVirtualMemory;
    uintptr_t NtWriteVirtualMemory;
    uintptr_t NtQueryVirtualMemory;
    uintptr_t NtMapViewOfSection;

    // Процессы и объекты
    uintptr_t NtOpenProcess;
    uintptr_t NtDuplicateObject;
    uintptr_t NtQueryInformationProcess;
    uintptr_t NtQuerySystemInformation;

    // Потоки и контекст
    uintptr_t NtQueueApcThread;
    uintptr_t NtGetContextThread;
    uintptr_t NtSetContextThread;
    uintptr_t NtResumeThread;
    uintptr_t NtSuspendThread;

    // Синхронизация / handles
    uintptr_t NtFlushInstructionCache;
    uintptr_t NtClose;

    // ntdll Rtl* (direct calls, not Syscall_* stubs)
    uintptr_t RtlAddVectoredExceptionHandler;
    uintptr_t RtlRemoveVectoredExceptionHandler;
};

// ==================== SYSCALL FUNCTIONS ====================
extern "C" {
    // Memory Operations
    extern NTSTATUS Syscall_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    extern NTSTATUS Syscall_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    extern NTSTATUS Syscall_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
    extern NTSTATUS Syscall_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
    extern NTSTATUS Syscall_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
    extern NTSTATUS Syscall_NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

    // Process Operations
    extern NTSTATUS Syscall_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    extern NTSTATUS Syscall_NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
    extern NTSTATUS Syscall_NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    extern NTSTATUS Syscall_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    // Thread Operations
    extern NTSTATUS Syscall_NtQueueApcThread(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
    extern NTSTATUS Syscall_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    extern NTSTATUS Syscall_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    extern NTSTATUS Syscall_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
    extern NTSTATUS Syscall_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    extern NTSTATUS Syscall_NtMapViewOfSection( HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,PSIZE_T ViewSize,SECTION_INHERIT InheritDisposition,ULONG AllocationType, ULONG Win32Protect);
    extern NTSTATUS Syscall_NtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
    extern NTSTATUS Syscall_NtClose(HANDLE Handle);
}