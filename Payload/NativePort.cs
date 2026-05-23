using System.Runtime.InteropServices;
using static Retention.Core.NativeConstants;

namespace Retention;

// Remote process helpers: handle table walk, donor duplication, PEB/Ldr reads — all via Nt* from Core.Api.
public static unsafe class NativePort
{
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_DUP_HANDLE = 0x0040;
    static readonly uint OaSize = (uint)Marshal.SizeOf<OBJECT_ATTRIBUTES>();

    // Avoid System.IO — strip path manually for comparing BaseDllName to "client.dll" etc.
    private static string FileNameFromPath(string path)
    {
        for (int i = path.Length; --i >= 0;)
        {
            char c = path[i];
            if (c == '\\' || c == '/') return path[(i + 1)..];
        }
        return path;
    }

    // SystemExtendedHandleInformation often needs a bigger buffer than the first probe; grow until NtQuery succeeds.
    public static bool QuerySystemHandlesWithGrowableBuffer(ref void* buffer, ref nuint byteSize)
    {
        var a = Core.Api;
        for (;;)
        {
            if (buffer == null)
            {
                void* p = null;
                nuint sz = byteSize;
                // Current process pseudo-handle (-1) for local allocations.
                if (a.NtAllocate((IntPtr)(-1), &p, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != STATUS_SUCCESS)
                    return false;
                buffer = p;
                byteSize = sz;
            }
            int st = a.NtQuerySystemInformation((int)SystemExtendedHandleInformation, buffer, (uint)byteSize, null);
            if (st == STATUS_SUCCESS) return true;
            if (st != kNtStatusBufferTooSmall) return false;
            void* toFree = buffer;
            nuint freed = 0;
            a.NtFree((IntPtr)(-1), &toFree, &freed, MEM_RELEASE);
            buffer = null;
            byteSize += 1024 * 256;
        }
    }

    public static void FreeAllocation(ref void* ptr)
    {
        if (ptr == null) return;
        void* p = ptr;
        nuint freed = 0;
        Core.Api.NtFree((IntPtr)(-1), &p, &freed, MEM_RELEASE);
        ptr = null;
    }

    // Remote process DLL base by module name (C++ FindRemoteModuleBase analogue).
    // remoteLdr = remote PEB->Ldr; +0x10 = &InLoadOrderModuleList.Flink (kernel list head). Walk with NtRead only.
    public static nuint FindRemoteModuleBase(IntPtr hProcess, nuint remoteLdr, string moduleName)
    {
        var a = Core.Api;
        nuint listHead = remoteLdr + 0x10;
        nuint currentEntry = 0;
        if (a.NtRead(hProcess, (void*)listHead, &currentEntry, (nuint)sizeof(nuint), null) != STATUS_SUCCESS)
            return 0;
        char* nameBuf = stackalloc char[513];
        while (currentEntry != listHead)
        {
            LDR_DATA_TABLE_ENTRY entry;
            if (a.NtRead(hProcess, (void*)currentEntry, &entry, (nuint)sizeof(LDR_DATA_TABLE_ENTRY), null) != STATUS_SUCCESS)
                break;
            nuint nextEntry = (nuint)(nint)entry.InLoadOrderLinks.Flink;
            int wcharLen = entry.BaseDllName.Length / 2;
            if (wcharLen > 0 && wcharLen < 512 && entry.BaseDllName.Buffer != IntPtr.Zero
                && a.NtRead(hProcess, (void*)entry.BaseDllName.Buffer, nameBuf, (nuint)entry.BaseDllName.Length, null) == STATUS_SUCCESS)
            {
                nameBuf[wcharLen] = '\0';
                var slice = new string(nameBuf, 0, wcharLen);
                if (string.Equals(slice, moduleName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(FileNameFromPath(slice), moduleName, StringComparison.OrdinalIgnoreCase))
                    return (nuint)(nint)entry.DllBase;
            }
            if (nextEntry == 0) break;
            currentEntry = nextEntry;
        }
        return 0;
    }

    // Find our own process handle entry in the global handle table to learn the "Process" object type index (for filtering duplicates).
    public static bool ResolveProcessObjectTypeIndex(ref ushort outIndex)
    {
        var a = Core.Api;
        uint myPid = (uint)Environment.ProcessId;
        var selfCid = new CLIENT_ID { UniqueProcess = (IntPtr)(nuint)myPid, UniqueThread = IntPtr.Zero };
        var selfOa = new OBJECT_ATTRIBUTES { Length = OaSize };
        IntPtr hSelf = IntPtr.Zero;
        if (a.NtOpenProcess(&hSelf, PROCESS_QUERY_LIMITED_INFORMATION, &selfOa, &selfCid) != STATUS_SUCCESS || hSelf == IntPtr.Zero)
            return false;
        void* handleBuf = null;
        nuint handleBufSize = 1024 * 1024;
        if (!QuerySystemHandlesWithGrowableBuffer(ref handleBuf, ref handleBufSize))
        {
            _ = a.NtClose(hSelf);
            FreeAllocation(ref handleBuf);
            return false;
        }
        var info = (SYSTEM_HANDLE_INFORMATION_EX*)handleBuf;
        nuint count = (nuint)info->NumberOfHandles;
        var first = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX*)(info + 1);
        for (nuint i = 0; i < count; i++)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* e = first + i;
            if (e->UniqueProcessId == (UIntPtr)myPid && (nint)e->HandleValue == hSelf)
            {
                outIndex = e->ObjectTypeIndex;
                _ = a.NtClose(hSelf);
                FreeAllocation(ref handleBuf);
                return true;
            }
        }
        _ = a.NtClose(hSelf);
        FreeAllocation(ref handleBuf);
        return false;
    }

    // Scan donor's open handles: duplicate candidates with PROCESS_ALL_ACCESS, confirm UniqueProcessId matches targetPid via NtQueryInformationProcess.
    public static bool TryDuplicateFullControlHandle(
        IntPtr hDonor,
        SYSTEM_HANDLE_INFORMATION_EX* globalHandles,
        uint donorPid,
        uint targetPid,
        ushort processTypeIndex,
        ref IntPtr ioProcess)
    {
        var a = Core.Api;
        nuint count = (nuint)globalHandles->NumberOfHandles;
        var entries = (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX*)(globalHandles + 1);
        for (nuint i = 0; i < count; i++)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* entry = entries + i;
            if (entry->UniqueProcessId != (UIntPtr)donorPid || entry->ObjectTypeIndex != processTypeIndex
                || entry->GrantedAccess != kProcessFullControl)
                continue;
            IntPtr duplicated = IntPtr.Zero;
            int dupSt = a.NtDuplicateObject(hDonor, (IntPtr)(nint)entry->HandleValue, (IntPtr)(-1), &duplicated, 0, 0, kDuplicateSameAccess);
            if (dupSt != STATUS_SUCCESS)
            {
                if (duplicated != IntPtr.Zero) _ = a.NtClose(duplicated);
                continue;
            }
            PROCESS_BASIC_INFORMATION pbi;
            int qipSt = a.NtQueryInformationProcess(duplicated, 0, &pbi, (uint)sizeof(PROCESS_BASIC_INFORMATION), null);
            if (qipSt == STATUS_SUCCESS && pbi.UniqueProcessId == (UIntPtr)targetPid)
            {
                ioProcess = duplicated;
                return true;
            }
            _ = a.NtClose(duplicated);
        }
        return false;
    }

    // Ported flow: system handle snapshot → resolve process type → try privileged handles from donor processes → open target → read PEB+0x18 (Ldr).
    public static int RunPortedMain(uint targetPid)
    {
        Core.TargetPid = targetPid;
        void* handleTableBuffer = null;
        nuint handleTableSize = 1024 * 1024;
        if (!QuerySystemHandlesWithGrowableBuffer(ref handleTableBuffer, ref handleTableSize))
        {
            FreeAllocation(ref handleTableBuffer);
            return 1;
        }
        var globalHandles = (SYSTEM_HANDLE_INFORMATION_EX*)handleTableBuffer;
        uint myPid = (uint)Environment.ProcessId;
        uint procListSize = 0;
        Core.Api.NtQuerySystemInformation((int)SystemProcessInformation, null, 0, &procListSize);
        procListSize += 0x2000;
        void* procListP = null;
        nuint procListAlloc = procListSize;
        int allocProc = Core.Api.NtAllocate((IntPtr)(-1), &procListP, 0, &procListAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        void* procListBuffer = allocProc == STATUS_SUCCESS ? procListP : null;
        ushort processTypeIndex = 0;
        if (!ResolveProcessObjectTypeIndex(ref processTypeIndex))
        {
            FreeAllocation(ref handleTableBuffer);
            FreeAllocation(ref procListBuffer);
            return 1;
        }
        if (allocProc == STATUS_SUCCESS)
        {
            Core.Api.NtQuerySystemInformation((int)SystemProcessInformation, procListBuffer, (uint)procListAlloc, &procListSize);
            ReadOnlySpan<string> kDonors = ["csrss.exe", "lsass.exe", "Steam.exe", "Discord.exe", "svchost.exe"];
            bool duplicated = false;
            foreach (var donorName in kDonors)
            {
                if (duplicated) break;
                for (SYSTEM_PROCESS_INFORMATION* scan = (SYSTEM_PROCESS_INFORMATION*)procListBuffer;;)
                {
                    if (scan->ImageName.Buffer != IntPtr.Zero && scan->ImageName.Length > 0)
                    {
                        string img = new string((char*)scan->ImageName.Buffer, 0, scan->ImageName.Length / 2);
                        if ((string.Equals(img, donorName, StringComparison.OrdinalIgnoreCase)
                             || string.Equals(FileNameFromPath(img), donorName, StringComparison.OrdinalIgnoreCase))
                            && (uint)(nint)scan->UniqueProcessId != myPid)
                        {
                            uint donorPid = (uint)(nint)scan->UniqueProcessId;
                            var dCid = new CLIENT_ID { UniqueProcess = (IntPtr)(nuint)donorPid, UniqueThread = IntPtr.Zero };
                            var dOa = new OBJECT_ATTRIBUTES { Length = OaSize };
                            IntPtr hDonor = IntPtr.Zero;
                            if (Core.Api.NtOpenProcess(&hDonor, PROCESS_DUP_HANDLE, &dOa, &dCid) == STATUS_SUCCESS && hDonor != IntPtr.Zero)
                            {
                                IntPtr previous = Core.hProcess;
                                if (TryDuplicateFullControlHandle(hDonor, globalHandles, donorPid, targetPid, processTypeIndex, ref Core.hProcess))
                                {
                                    if (previous != IntPtr.Zero) _ = Core.Api.NtClose(previous);
                                    duplicated = true;
                                    _ = Core.Api.NtClose(hDonor);
                                    break;
                                }
                                _ = Core.Api.NtClose(hDonor);
                            }
                        }
                    }
                    if (scan->NextEntryOffset == 0) break;
                    scan = (SYSTEM_PROCESS_INFORMATION*)((byte*)scan + scan->NextEntryOffset);
                }
            }
        }
        var cid = new CLIENT_ID { UniqueProcess = (IntPtr)(nuint)targetPid, UniqueThread = IntPtr.Zero };
        var oa = new OBJECT_ATTRIBUTES { Length = OaSize };
        IntPtr hOpened = IntPtr.Zero;
        Core.Api.NtOpenProcess(&hOpened, kOpenProcessDesiredAccess, &oa, &cid);
        PROCESS_BASIC_INFORMATION pbi;
        Core.Api.NtQueryInformationProcess(hOpened, 0, &pbi, (uint)sizeof(PROCESS_BASIC_INFORMATION), null);
        nuint remoteLdr = 0;
        // PEB + 0x18 on x64 = PPEB_LDR_DATA Ldr — start of module list in target VA space.
        if (pbi.PebBaseAddress != IntPtr.Zero)
            Core.Api.NtRead(hOpened, (void*)((nuint)(nint)pbi.PebBaseAddress + 0x18), &remoteLdr, (nuint)sizeof(nuint), null);
        Core.OpenedProcessHandle = hOpened;
        Core.RemoteLdr = remoteLdr;
        FreeAllocation(ref handleTableBuffer);
        FreeAllocation(ref procListBuffer);
        return 0;
    }
}
