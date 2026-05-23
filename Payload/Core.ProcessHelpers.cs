using static Retention.Core.NativeConstants;

namespace Retention;

public unsafe partial class Core
{
    public unsafe static class NativeTools
    {
        // SystemProcessInformation buffer walk — find ImageName match, return UniqueProcessId as uint.
        public static uint FindProcessIdByName(string processName)
        {
            uint size = 0;
            Api.NtQuerySystemInformation((int)SystemProcessInformation, null, 0, &size);
            if (size == 0) return 0;
            nuint regionSize = size + 0x2000;
            void* buffer = null;
            if (Api.NtAllocate((IntPtr)(-1), &buffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != STATUS_SUCCESS || buffer == null)
                return 0;
            uint pid = 0;
            if (Api.NtQuerySystemInformation((int)SystemProcessInformation, buffer, (uint)regionSize, &size) == STATUS_SUCCESS)
            {
                for (SYSTEM_PROCESS_INFORMATION* p = (SYSTEM_PROCESS_INFORMATION*)buffer;;)
                {
                    if (p->ImageName.Buffer != IntPtr.Zero && p->ImageName.Length is > 0 and < 512)
                    {
                        try
                        {
                            if (new string((char*)p->ImageName.Buffer, 0, p->ImageName.Length / 2).Equals(processName, StringComparison.OrdinalIgnoreCase))
                            {
                                pid = (uint)p->UniqueProcessId;
                                break;
                            }
                        }
                        catch { }
                    }
                    if (p->NextEntryOffset == 0) break;
                    p = (SYSTEM_PROCESS_INFORMATION*)((byte*)p + p->NextEntryOffset);
                }
            }
            nuint freeSize = 0;
            Api.NtFree((IntPtr)(-1), &buffer, &freeSize, MEM_RELEASE);
            return pid;
        }
    }

    // Current process PEB address via NtQueryInformationProcess(-1, ProcessBasicInformation).
    // -1 = NtCurrentProcess(); class 0 = ProcessBasicInformation → PebBaseAddress.
    public static unsafe nuint GetMyPeb()
    {
        if (Api.NtQueryInformationProcess == null) return 0;
        PROCESS_BASIC_INFORMATION pbi = default;
        if (Api.NtQueryInformationProcess((IntPtr)(-1), 0, &pbi, (uint)sizeof(PROCESS_BASIC_INFORMATION), null) != STATUS_SUCCESS)
            return 0;
        return (nuint)(nint)pbi.PebBaseAddress;
    }

    // Current-process module base by DLL name via PEB -> Ldr -> InLoadOrderModuleList.
    public static unsafe nuint GetModuleBase(string moduleName)
    {
        if (string.IsNullOrEmpty(moduleName)) return 0;
        nuint peb = GetMyPeb();
        if (peb == 0) return 0;

        // PEB.Ldr at +0x18 (x64); InLoadOrderModuleList at Ldr+0x10 — same walk as ntdll would use locally.
        nuint ldr = *(nuint*)(void*)(peb + 0x18);
        if (ldr == 0) return 0;

        nuint anchor = ldr + 0x10;
        nuint cur = *(nuint*)(void*)anchor;
        ReadOnlySpan<char> want = moduleName.AsSpan();
        for (int n = 0; n < 512 && cur != 0 && cur != anchor; n++)
        {
            var e = *(LDR_DATA_TABLE_ENTRY*)(void*)cur;
            int wcharLen = e.BaseDllName.Length / 2;
            if (wcharLen > 0 && wcharLen < 512 && e.BaseDllName.Buffer != IntPtr.Zero)
            {
                char* p = (char*)(void*)e.BaseDllName.Buffer;
                if (ModuleNameEqualsInsensitive(p, wcharLen, want))
                    return (nuint)(nint)e.DllBase;
            }
            cur = (nuint)(nint)e.InLoadOrderLinks.Flink;
        }
        return 0;
    }

    // BaseDllName is UTF-16; compare case-insensitive without allocating per character (hot path in loader walk).
    private static bool ModuleNameEqualsInsensitive(char* p, int wcharLen, ReadOnlySpan<char> want)
    {
        if (wcharLen != want.Length) return false;
        for (int i = 0; i < want.Length; i++)
        {
            char c = p[i];
            if (c is >= 'A' and <= 'Z') c = (char)(c + 32);
            char w = want[i];
            if (w is >= 'A' and <= 'Z') w = (char)(w + 32);
            if (c != w) return false;
        }
        return true;
    }

    // If bridge Rtl* slots are null, resolve from local ntdll image via PEB loader walk.
    // Fallback when SyscallBridge Rtl slots are null: walk local loader list, set NTDLL.ntBase, fill Rtl* from export hashes.
    private static unsafe void TryWireRtlFromLocalNtdllIfMissing(ref InternalBridge api)
    {
        if (api.RtlAddVectoredExceptionHandler != null && api.RtlRemoveVectoredExceptionHandler != null)
            return;
        if (api.NtQueryInformationProcess == null)
            return;

        nuint peb = GetMyPeb();
        if (peb == 0) return;

        nuint ldr = *(nuint*)(void*)(peb + 0x18);
        if (ldr == 0) return;

        nuint listHead = ldr + 0x10;
        nuint cur = *(nuint*)(void*)listHead;
        nuint ntBase = 0;
        for (int n = 0; n < 200 && cur != 0 && cur != listHead; n++)
        {
            var e = *(LDR_DATA_TABLE_ENTRY*)(void*)cur;
            int wcharLen = e.BaseDllName.Length / 2;
            if (wcharLen == 9 && e.BaseDllName.Buffer != IntPtr.Zero)
            {
                char* p = (char*)(void*)e.BaseDllName.Buffer;
                if (ModuleNameEqualsInsensitive(p, wcharLen, "ntdll.dll"))
                {
                    ntBase = (nuint)(nint)e.DllBase;
                    break;
                }
            }
            cur = (nuint)(nint)e.InLoadOrderLinks.Flink;
        }
        if (ntBase == 0) return;

        NTDLL.ntBase = ntBase;
        // Cast export VA to exact stdcall function pointer type the bridge expects (handler is raw nint per RtlAdd signature).
        if (api.RtlAddVectoredExceptionHandler == null)
        {
            nuint addr = NTDLL.GetExportAddress(ntBase, HashExportRtlAddVectoredExceptionHandler);
            if (addr != 0)
                api.RtlAddVectoredExceptionHandler = (delegate* unmanaged[Stdcall]<uint, nint, nint>)(void*)addr;
        }
        if (api.RtlRemoveVectoredExceptionHandler == null)
        {
            nuint addr = NTDLL.GetExportAddress(ntBase, HashExportRtlRemoveVectoredExceptionHandler);
            if (addr != 0)
                api.RtlRemoveVectoredExceptionHandler = (delegate* unmanaged[Stdcall]<nint, uint>)(void*)addr;
        }
    }
}
