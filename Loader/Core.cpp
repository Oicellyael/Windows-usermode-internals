#include "Core.h"

// ��� ���������� ������ ������ � EXTERN � ����� .asm �����
extern "C" {
    uintptr_t IndirectSyscallJumpAddress = 0;

    // ��������� ������ (SSN)
    uintptr_t SsnNtOpenProcess = 0;
    uintptr_t SsnNtReadVirtualMemory = 0;
    uintptr_t SsnNtWriteVirtualMemory = 0;
    uintptr_t SsnNtAllocateVirtualMemory = 0;
    uintptr_t SsnNtFreeVirtualMemory = 0;
    uintptr_t SsnNtProtectVirtualMemory = 0;
    uintptr_t SsnNtDuplicateObject = 0;

    uintptr_t SsnNtQuerySystemInformation = 0;
    uintptr_t SsnNtQueryInformationProcess = 0;

    uintptr_t SsnNtQueueApcThread = 0;
    uintptr_t SsnNtGetContextThread = 0;
    uintptr_t SsnNtSetContextThread = 0;
    uintptr_t SsnNtResumeThread = 0;
    uintptr_t SsnNtSuspendThread = 0;

	uintptr_t SsnNtQueryVirtualMemory = 0;
	uintptr_t SsnNtMapViewOfSection = 0;
	uintptr_t SsnNtFlushInstructionCache = 0;

	uintptr_t SsnNtClose = 0;

	// RTL функции (обычные адреса, не syscalls)
	uintptr_t RtlAddVectoredExceptionHandlerAddr = 0;
	uintptr_t RtlRemoveVectoredExceptionHandlerAddr = 0;
}

uintptr_t ntdllBase = 0;

namespace Fog::Core {

    static bool ResolveSsnByHash(DWORD hash, uintptr_t* ssnSlot) {
        if (!ssnSlot || !ntdllBase) {
            return false;
        }
        const uintptr_t functionAddress = GetExportAddress(ntdllBase, hash);
        if (!functionAddress) {
            return false;
        }
        const DWORD ssn = ExtractSSN(ntdllBase, functionAddress);
        if (!ssn) {
            return false;
        }
        *ssnSlot = ssn;
        return true;
    }

    DWORD HashString(const char* word) {
        DWORD hash = 4291;
        int c;
        while ((c = *word++)) {
            if (isupper(c)) c = c + 32;
            hash = ((hash << 5) + hash) + c;
        }
        return hash;
    }

    uintptr_t GetModuleBase(const wchar_t* moduleName) {
        uintptr_t peb = GetMyPeb();
        if (!peb) return 0;

        uintptr_t ldr = *(uintptr_t*)(peb + 0x18);
        uintptr_t anchor = (ldr + 0x10);
        uintptr_t current = *(uintptr_t*)anchor;

        do {
            uintptr_t bufferAddress = *(uintptr_t*)(current + 0x60);
            if (bufferAddress != 0) {
                wchar_t* dllName = (wchar_t*)bufferAddress;
                if (_wcsicmp(dllName, moduleName) == 0) {
                    return *(uintptr_t*)(current + 0x30);
                }
            }
            current = *(uintptr_t*)current;
        } while (current != anchor);

        return 0;
    }

    uintptr_t GetExportAddress(uintptr_t moduleBase, DWORD targetHash) {
        if (!moduleBase) return 0;

        DWORD PeStart = *(DWORD*)(moduleBase + 0x3C);
        DWORD exportRVA = *(DWORD*)(moduleBase + PeStart + 0x88);
        uintptr_t EDAddress = moduleBase + exportRVA;

        DWORD numNames = *(DWORD*)(EDAddress + 0x18);
        uintptr_t namesAddr = moduleBase + *(DWORD*)(EDAddress + 0x20);
        uintptr_t ordinalsAddr = moduleBase + *(DWORD*)(EDAddress + 0x24);
        uintptr_t functionsAddr = moduleBase + *(DWORD*)(EDAddress + 0x1C);

        for (DWORD i = 0; i < numNames; i++) {
            DWORD name = *(DWORD*)(namesAddr + i * 4);
            char* namestr = (char*)(moduleBase + name);
            if (HashString(namestr) == targetHash) {
                WORD ordinal = *(WORD*)(ordinalsAddr + i * 2);
                DWORD functionRVA = *(DWORD*)(functionsAddr + (ordinal * 4));
                return moduleBase + functionRVA;
            }
        }
        return 0;
    }

    DWORD GetModuleSize(uintptr_t moduleBase) {
        auto* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
        auto* pNtHdrs = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase + pDosHdr->e_lfanew);
        return pNtHdrs->OptionalHeader.SizeOfImage;
    }

    DWORD ExtractSSN(uintptr_t moduleBase, uintptr_t address) {
        if (!address || !moduleBase) return 0;

        const BYTE expected[] = { 0x4C, 0x8B, 0xD1, 0xB8 }; // mov r10, rcx; mov eax, SSN
        DWORD moduleSize = GetModuleSize(moduleBase);
        uintptr_t moduleEnd = moduleBase + moduleSize;


        if (memcmp((BYTE*)address, expected, 4) == 0) {

            for (size_t i = 0; i < 32; i++) {
                if (address + i + 1 >= moduleEnd) break;
                if (*(BYTE*)(address + i) == 0x0F && *(BYTE*)(address + i + 1) == 0x05) {
                    IndirectSyscallJumpAddress = address + i;
                    break;
                }
            }
            return *(DWORD*)(address + 4);
        }

  
        for (WORD i = 1; i < 500; i++) {
            uintptr_t neighbor_up = address - (i * 0x20);
            if (neighbor_up >= moduleBase && memcmp((BYTE*)neighbor_up, expected, 4) == 0) {
                return *(DWORD*)(neighbor_up + 4) + i;
            }

            uintptr_t neighbor_down = address + (i * 0x20);
            if (neighbor_down + 4 < moduleEnd && memcmp((BYTE*)neighbor_down, expected, 4) == 0) {
                return *(DWORD*)(neighbor_down + 4) - i;
            }
        }

        return 0;
    }

    bool Initialize() {
        ntdllBase = GetModuleBase(L"ntdll.dll");
        if (!ntdllBase) return false;

        if (!ResolveSsnByHash(HASH_NtOpenProcess, &SsnNtOpenProcess) ||
            !ResolveSsnByHash(HASH_NtReadVirtualMemory, &SsnNtReadVirtualMemory) ||
            !ResolveSsnByHash(HASH_NtWriteVirtualMemory, &SsnNtWriteVirtualMemory) ||
            !ResolveSsnByHash(HASH_NtAllocateVirtualMemory, &SsnNtAllocateVirtualMemory) ||
            !ResolveSsnByHash(HASH_NtFreeVirtualMemory, &SsnNtFreeVirtualMemory) ||
            !ResolveSsnByHash(HASH_NtProtectVirtualMemory, &SsnNtProtectVirtualMemory) ||
            !ResolveSsnByHash(HASH_NtDuplicateObject, &SsnNtDuplicateObject) ||
            !ResolveSsnByHash(HASH_NtQuerySystemInformation, &SsnNtQuerySystemInformation) ||
            !ResolveSsnByHash(HASH_NtQueryInformationProcess, &SsnNtQueryInformationProcess) ||
            !ResolveSsnByHash(HASH_NtQueueApcThread, &SsnNtQueueApcThread) ||
            !ResolveSsnByHash(HASH_NtGetContextThread, &SsnNtGetContextThread) ||
            !ResolveSsnByHash(HASH_NtSetContextThread, &SsnNtSetContextThread) ||
            !ResolveSsnByHash(HASH_NtResumeThread, &SsnNtResumeThread) ||
            !ResolveSsnByHash(HASH_NtSuspendThread, &SsnNtSuspendThread) ||
            !ResolveSsnByHash(HASH_NtQueryVirtualMemory, &SsnNtQueryVirtualMemory) ||
            !ResolveSsnByHash(HASH_NtMapViewOfSection, &SsnNtMapViewOfSection) ||
            !ResolveSsnByHash(HASH_NtFlushInstructionCache, &SsnNtFlushInstructionCache) ||
            !ResolveSsnByHash(HASH_NtClose, &SsnNtClose)) {
            return false;
        }

        if (!IndirectSyscallJumpAddress) {
            return false;
        }

        // Rtl* — обычные экспорты ntdll, не syscall-стабы.
        RtlAddVectoredExceptionHandlerAddr =
            GetExportAddress(ntdllBase, HASH_RtlAddVectoredExceptionHandler);
        RtlRemoveVectoredExceptionHandlerAddr =
            GetExportAddress(ntdllBase, HASH_RtlRemoveVectoredExceptionHandler);
        if (!RtlAddVectoredExceptionHandlerAddr || !RtlRemoveVectoredExceptionHandlerAddr) {
            return false;
        }

        return true;
    }
}