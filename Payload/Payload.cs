using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Retention.Core.NativeConstants;

namespace Retention;

// Local-module export resolver: parse PE export directory in *this* process (raw pointers), match export name hash.
public static unsafe class NTDLL
{
    public static nuint ntBase;

    // Same rolling hash as typical C++ donor code — compares against precomputed constants (no export name strings in binary).
    public static uint MyHasher(byte* word)
    {
        uint hash = 4291;
        int c;
        while ((c = *word++) != 0)
        {
            if (c is >= 'A' and <= 'Z') c += 32;
            hash = ((hash << 5) + hash) + (uint)c;
        }
        return hash;
    }

   
    public static nuint GetExportAddress(nuint moduleBase, uint targetHash)
    {
        if (moduleBase == 0) return 0;
        // PE: e_lfanew at +0x3C; optional header export table RVA at +0x88 for PE32+ (x64 image).
        uint peStart = *(uint*)(void*)(moduleBase + 0x3C);
        uint exportRva = *(uint*)(void*)(moduleBase + peStart + 0x88);
        nuint edAddress = moduleBase + exportRva;
        uint numNames = *(uint*)(void*)(edAddress + 0x18);
        if (numNames > 0x100000) return 0;
        nuint namesAddr = moduleBase + *(uint*)(void*)(edAddress + 0x20);
        nuint ordinalsAddr = moduleBase + *(uint*)(void*)(edAddress + 0x24);
        nuint functionsAddr = moduleBase + *(uint*)(void*)(edAddress + 0x1C);
        for (uint i = 0; i < numNames; i++)
        {
            uint nameRva = *(uint*)(void*)(namesAddr + i * 4);
            byte* namestr = (byte*)(void*)(moduleBase + nameRva);
            if (MyHasher(namestr) != targetHash) continue;
            ushort ordinal = *(ushort*)(void*)(ordinalsAddr + i * 2);
            uint functionRva = *(uint*)(void*)(functionsAddr + (uint)(ordinal * 4));
            return moduleBase + functionRva;
        }
        return 0;
    }

    // Convenience wrapper when ntBase is already set.
    public static nuint GetFunctionAddress(uint targetHash) => GetExportAddress(ntBase, targetHash);
}
public static unsafe class HeaderStripper
{
    // Wipes DOS/PE headers in-place (RWX via NtProtect on current process) — hides obvious PE signatures at moduleBase.
    public static unsafe void Strip(IntPtr dllBase)
    {
        if (dllBase == IntPtr.Zero) return;

        byte* ptr = (byte*)dllBase;

        if (*(ushort*)ptr != 0x5A4D) return;

        int e_lfanew = *(int*)(ptr + 0x3C);

        if (*(uint*)(ptr + e_lfanew) != 0x4550) return;

        nuint headerSize = *(uint*)(ptr + e_lfanew + 0x54);

        void* basePtr = (void*)dllBase;
        uint oldProtect = 0;
        var a = Core.Api;

        if (a.NtProtect((IntPtr)(-1), &basePtr, &headerSize, 0x04, &oldProtect) == 0)
        {
            new Span<byte>(ptr, (int)headerSize).Clear();
            uint temp;
            a.NtProtect((IntPtr)(-1), &basePtr, &headerSize, oldProtect, &temp);
        }
    }
}
// Entry from native: SyscallBridge → typed function pointers; payload runs here (AOT-friendly, no Win32 imports in app code).
public unsafe partial class Core
{
    private static InternalBridge _api;
    public static InternalBridge Api => _api;
    public static IntPtr hProcess;
    public static uint TargetPid;
    public static IntPtr OpenedProcessHandle;
    public static nuint RemoteLdr;
    public static GameRemoteModules GameModules;
    // Trap VAs compared against EXCEPTION_RECORD.ExceptionAddress in VEH.
    // VA of hardware breakpoint #0 / #1 — compared in OnTrapVEH against ExceptionAddress (see SetTrap).
    public static nuint HwTrapAddr0;
    public static nuint HwTrapAddr1;
    // True for the lifetime of RunPayload try-block: same thread periodically re-arms DR (OnTrapVEH clears DR each hit; -2 = caller thread only).
    private static volatile bool s_trapHooksSessionActive;

    [UnmanagedCallersOnly(EntryPoint = "InitializeCore")]
    public static void InitializeCore(SyscallBridge* bridge, IntPtr moduleBase)
    {
        if (bridge == null) { _api = default; return; }
        // Field-wise copy from native SyscallBridge — avoids reinterpreting mismatched layouts as InternalBridge*.
        _api = BridgeFill.FromSyscallBridge(bridge);
        // If bridge left Rtl slots null, resolve RtlAdd/RtlRemove from local ntdll exports (still Nt-only path).
        TryWireRtlFromLocalNtdllIfMissing(ref _api);

        // Strip PE headers at our module base (optional stealth / smaller footprint in memory scans).
       // HeaderStripper.Strip(moduleBase);

        try { RunPayload(); } catch { }
    }

    public static class NativeConstants
    {
        // NtOpenProcess / duplication / memory flags / CONTEXT — keep magic values in one place for audits and offsetof parity with C++ probes.
        public const uint kOpenProcessDesiredAccess = 0x0438;
        public const uint kDuplicateSameAccess = 0x00000002;
        public const uint kProcessFullControl = 0x001FFFFF;
        public const int kNtStatusBufferTooSmall = unchecked((int)0xC0000004);
        public const int STATUS_SUCCESS = 0;
        public const uint SystemProcessInformation = 5;
        public const uint SystemExtendedHandleInformation = 64;
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint MEM_RELEASE = 0x00008000;
        public const uint PAGE_READWRITE = 0x04;
        // Base CONTEXT_AMD64 prefix (winnt.h).
        public const uint ContextAmd64 = 0x00100000;
        // CONTEXT_DEBUG_REGISTERS selector (Dr0-Dr7).
        public const uint ContextAmd64DebugRegisters = ContextAmd64 | 0x10;
        // Native amd64 CONTEXT size (sizeof(CONTEXT) = 1232).
        public const int ContextAmd64RecordBytes = 1232;
        // amd64 offsetof(CONTEXT, ...) values from x64 SDK probe.
        public const nuint OffsetContext_ContextFlags = 48;
        public const nuint OffsetContext_Dr0 = 72;
        public const nuint OffsetContext_Dr1 = 80;
        public const nuint OffsetContext_Dr7 = 112;
        public const nuint OffsetContext_Rax = 120;
        public const nuint OffsetContext_Rsp = 152;
        public const nuint OffsetContext_Rip = 248;
        // MyHasher("RtlAddVectoredExceptionHandler") export hash.
        public const uint HashExportRtlAddVectoredExceptionHandler = 0x1CB8A887;
        // MyHasher("RtlRemoveVectoredExceptionHandler") export hash.
        public const uint HashExportRtlRemoveVectoredExceptionHandler = 0xA7C9312C;
        public const uint HASH_AMSI_SCAN_BUFFER = 0x27D9EE2C;
        public const uint HASH_ETW_EVENT_WRITE = 0x4CA9D500;
    }

   
    public static unsafe void SetTrap()
    {
        if (Api.NtGetContext == null || Api.NtSetContext == null)
            return;

        nuint bAmsi = GetModuleBase("amsi.dll");
        nuint ntdll = GetModuleBase("ntdll.dll");
        if (ntdll != 0)
            NTDLL.ntBase = ntdll;
        nuint addrEtw = NTDLL.GetExportAddress(NTDLL.ntBase, HASH_ETW_EVENT_WRITE);
        nuint addrFirst = NTDLL.GetExportAddress(bAmsi, HASH_AMSI_SCAN_BUFFER);
        HwTrapAddr0 = addrFirst;
        HwTrapAddr1 = addrEtw;
        if (addrFirst == 0 && addrEtw == 0)
            return;

        // Raw CONTEXT buffer: managed CONTEXT64 type in Struct.cs contains arrays — not blittable for NtGet/NtSetContext.
        // Offsets = offsetof(CONTEXT, …) from your x64 probe; -2 = current thread pseudo-handle.
        int n = ContextAmd64RecordBytes;
        byte* ctx = stackalloc byte[n];
        new Span<byte>(ctx, n).Clear();
        *(uint*)(ctx + OffsetContext_ContextFlags) = ContextAmd64DebugRegisters;
        if (Api.NtGetContext((IntPtr)(-2), ctx, (uint)n) != STATUS_SUCCESS)
            return;
        if (addrFirst != 0)
            *(ulong*)(ctx + OffsetContext_Dr0) = (ulong)addrFirst;
        if (addrEtw != 0)
            *(ulong*)(ctx + OffsetContext_Dr1) = (ulong)addrEtw;
        // DR7: bit0 L0 (+ bit2 L1 if two slots) — local enable, RW/LEN left zero => execute, 1-byte.
        if (addrFirst != 0 && addrEtw != 0)
            *(ulong*)(ctx + OffsetContext_Dr7) = 0x5;
        else if (addrFirst != 0 || addrEtw != 0)
            *(ulong*)(ctx + OffsetContext_Dr7) = 1u << 0;
        _ = Api.NtSetContext((IntPtr)(-2), ctx, (uint)n);
    }

    // Call from the same thread as RunPayload (e.g. inside your own while(true)) so NtGetContext(-2) re-applies DR after OnTrapVEH cleared them.
    public static void RearmTrapHooksIfSessionActive()
    {
        if (s_trapHooksSessionActive && (HwTrapAddr0 != 0 || HwTrapAddr1 != 0))
            SetTrap();
    }

    // Clear DR0/DR1/DR7 on current thread to avoid immediate retrigger loops.
    private static unsafe void ClearCurrentThreadHardwareBreakpoints()
    {
        if (Api.NtGetContext == null || Api.NtSetContext == null)
            return;
        // One-shot: clear DR so the faulting instruction does not re-trigger immediately (see OnTrapVEH).
        int n = ContextAmd64RecordBytes;
        byte* ctx = stackalloc byte[n];
        new Span<byte>(ctx, n).Clear();
        *(uint*)(ctx + OffsetContext_ContextFlags) = ContextAmd64DebugRegisters;
        if (Api.NtGetContext((IntPtr)(-2), ctx, (uint)n) != STATUS_SUCCESS)
            return;
        *(ulong*)(ctx + OffsetContext_Dr0) = 0;
        *(ulong*)(ctx + OffsetContext_Dr1) = 0;
        *(ulong*)(ctx + OffsetContext_Dr7) = 0;
        _ = Api.NtSetContext((IntPtr)(-2), ctx, (uint)n);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    public static unsafe int OnTrapVEH(EXCEPTION_POINTERS* p)
    {
    if (p == null || p->ExceptionRecord == IntPtr.Zero || p->ContextRecord == IntPtr.Zero)
        return VectoredException.ContinueSearch;

    byte* er = (byte*)(void*)p->ExceptionRecord;
    nuint addr = *(nuint*)(er + 0x10); // ExceptionAddress

    // Если мы поймали наш капкан на AMSI или ETW
    if ((HwTrapAddr0 != 0 && addr == HwTrapAddr0) || (HwTrapAddr1 != 0 && addr == HwTrapAddr1))
    {
        // 1. FIX LEAK: Take the context that the system itself brought to us in VEH
        byte* ctx = (byte*)(void*)p->ContextRecord;

        // Clear the traps directly in the context memory (no NtSetContext!)
        *(ulong*)(ctx + OffsetContext_Dr0) = 0;
        *(ulong*)(ctx + OffsetContext_Dr1) = 0;
        *(ulong*)(ctx + OffsetContext_Dr7) = 0;

        // 2. FIX LOGIC: Jump through the function (EMULATION RET)
        // In x64, when a function is called (CALL), the return address is placed on the top of the stack [RSP]
        ulong currentRsp = *(ulong*)(ctx + OffsetContext_Rsp);
        ulong returnAddress = *(ulong*)currentRsp; // Read the return address

        if (addr == HwTrapAddr0) // If it's AmsiScanBuffer
        {
           // Return E_INVALIDARG (0x80070057) - the system will decide that the call is broken and will ignore AMSI
            *(ulong*)(ctx + OffsetContext_Rax) = 0x80070057;
        }
        else if (addr == HwTrapAddr1) // Если это EtwEventWrite
        {
        // Return 0 (SUCCESS) - the system will decide that the log was successfully written
            *(ulong*)(ctx + OffsetContext_Rax) = 0;
        }
        // Teleport the thread:
        // A) Set the instruction pointer (RIP) to the return address
        *(ulong*)(ctx + OffsetContext_Rip) = returnAddress;
        

            *(ulong*)(ctx + OffsetContext_Rsp) = currentRsp + 8;

        // Give the context to the system. It will apply our changes to the processor!
        return VectoredException.ContinueExecution;
    }

    return VectoredException.ContinueSearch;
}

    [StructLayout(LayoutKind.Sequential)]
    public static class Marker
    {
        public static readonly byte[] Signature =
            { 0xDE, 0xAD, 0xBE, 0xEF };
    }
    private static nuint _originalFnAddress;
private static void* _myNewTable = null;
[UnmanagedCallersOnly(EntryPoint = "MyAwesomeCallback", CallConvs = new[] { typeof(CallConvStdcall) })]
public static unsafe IntPtr MyHijackedFunction(IntPtr windowHandle, uint message, IntPtr wParam, IntPtr lParam)
{
    var original = (delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr, IntPtr, IntPtr>)_originalFnAddress;
    return original(windowHandle, message, wParam, lParam);
}

public static unsafe void SetupKernelCallback()
{
    IntPtr peb = (IntPtr)GetMyPeb();
    
    nuint* pTableInPeb = (nuint*)(peb + 0x58);
    int tries = 0;
    while (*pTableInPeb == 0 && tries++ < 100)
    {
        return;
    }
        if (_myNewTable != null && *pTableInPeb == (nuint)_myNewTable)
        {
            return;
        }
    nuint originalTableAddr = *pTableInPeb;
    if (originalTableAddr == 0) return;

    nuint tableSize = 0x1000;
    void* kernelCopy = NativeMemory.AlignedAlloc(tableSize, 16);
    Buffer.MemoryCopy((void*)originalTableAddr, kernelCopy, (long)tableSize, (long)tableSize);
    
    nuint* tableArray = (nuint*)kernelCopy;
    _originalFnAddress = tableArray[2];

    delegate* unmanaged[Stdcall]<IntPtr, uint, IntPtr, IntPtr, IntPtr> myHookPtr = &MyHijackedFunction;
    tableArray[2] = (nuint)myHookPtr;
    _myNewTable = kernelCopy;
    *pTableInPeb = (nuint)kernelCopy;
}
    private static void RunPayload()
    {
    
        uint target = 0;

        if(target == 0)
             Console.WriteLine("Waiting for process...");
        while (target == 0)
        {
            target = NativeTools.FindProcessIdByName(".exe");
            if (target == 0) Thread.Sleep(500);
        }

        if(target != 0)
            Console.WriteLine("[+]");

        // Remote handle/Ldr first: NtGet/NtSetContext on the loader thread right after HeaderStripper has caused AVs in practice.
        IntPtr veh = IntPtr.Zero;
        try
        {
            if (NativePort.RunPortedMain(target) != 0)
                return;
            // VEH must exist before hardware breakpoints can fire in this process.
            veh = VectoredException.RegisterFirst(&OnTrapVEH);
            s_trapHooksSessionActive = true;
            SetTrap();
            nuint cBase = 0, eBase = 0;
            // Poll remote PEB loader list until game DLLs appear (requires OpenedProcessHandle + RemoteLdr from RunPortedMain).
            while (cBase == 0 || eBase == 0)
            {
                if (OpenedProcessHandle != IntPtr.Zero && RemoteLdr != 0)
                {
                    if (cBase == 0) cBase = NativePort.FindRemoteModuleBase(OpenedProcessHandle, RemoteLdr, "client.dll");
                    if (eBase == 0) eBase = NativePort.FindRemoteModuleBase(OpenedProcessHandle, RemoteLdr, "engine2.dll");
                }
                if (cBase == 0 || eBase == 0) Thread.Sleep(500);
                SetupKernelCallback();
                RearmTrapHooksIfSessionActive();
            }
            RearmTrapHooksIfSessionActive();
            GameModules = new GameRemoteModules { client = cBase, engine2 = eBase };
            Console.WriteLine($"VEH handle: 0x{veh:X} (0 = RtlAdd failed or invalid handler)");
            Console.WriteLine(target);
            // Same thread as SetTrap: periodic re-arm after OnTrapVEH clears DR0/DR1. Loop forever so VEH stays registered (finally only on fault/exit).
        }
        finally
        {
            s_trapHooksSessionActive = false;
            if (veh != IntPtr.Zero)
                _ = VectoredException.Remove(veh);
        }
    

        Console.WriteLine("Payload executed");
    }
}
