using System.Runtime.InteropServices;

namespace Retention;

public struct GameRemoteModules
{
    public nuint client;
    public nuint engine2;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct SyscallBridge
{
    public IntPtr NtAllocateVirtualMemory;
    public IntPtr NtFreeVirtualMemory;
    public IntPtr NtProtectVirtualMemory;
    public IntPtr NtReadVirtualMemory;
    public IntPtr NtWriteVirtualMemory;
    public IntPtr NtQueryVirtualMemory;
    public IntPtr NtMapViewOfSection;
    public IntPtr NtOpenProcess;
    public IntPtr NtDuplicateObject;
    public IntPtr NtQueryInformationProcess;
    public IntPtr NtQuerySystemInformation;
    public IntPtr NtQueueApcThread;
    public IntPtr NtGetContextThread;
    public IntPtr NtSetContextThread;
    public IntPtr NtResumeThread;
    public IntPtr NtSuspendThread;
    public IntPtr NtFlushInstructionCache;
    public IntPtr NtClose;
    public IntPtr RtlAddVectoredExceptionHandler;
    public IntPtr RtlRemoveVectoredExceptionHandler;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXCEPTION_POINTERS
{
    public IntPtr ExceptionRecord;
    public IntPtr ContextRecord;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct InternalBridge
{
    public delegate* unmanaged[Stdcall]<IntPtr, void**, nuint, nuint*, uint, uint, int> NtAllocate;
    public delegate* unmanaged[Stdcall]<IntPtr, void**, nuint*, uint, int> NtFree;
    public delegate* unmanaged[Stdcall]<IntPtr, void**, nuint*, uint, uint*, int> NtProtect;
    public delegate* unmanaged[Stdcall]<IntPtr, void*, void*, nuint, nuint*, int> NtRead;
    public delegate* unmanaged[Stdcall]<IntPtr, void*, void*, nuint, nuint*, int> NtWrite;
    public delegate* unmanaged[Stdcall]<IntPtr, void*, int, void*, nuint, nuint*, int> NtQueryVirtual;
    public delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void**, nuint, nuint, long*, nuint*, int, uint, uint, int> NtMapView;
    public delegate* unmanaged[Stdcall]<IntPtr*, uint, void*, void*, int> NtOpenProcess;
    public delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, IntPtr*, uint, uint, uint, int> NtDuplicateObject;
    public delegate* unmanaged[Stdcall]<IntPtr, int, void*, uint, uint*, int> NtQueryInformationProcess;
    public delegate* unmanaged[Stdcall]<int, void*, uint, uint*, int> NtQuerySystemInformation;
    public delegate* unmanaged[Stdcall]<IntPtr, void*, void*, void*, void*, int> NtQueueApc;
    public delegate* unmanaged[Stdcall]<IntPtr, void*, uint, int> NtGetContext;
    public delegate* unmanaged[Stdcall]<IntPtr, void*, uint, int> NtSetContext;
    public delegate* unmanaged[Stdcall]<IntPtr, uint*, int> NtResume;
    public delegate* unmanaged[Stdcall]<IntPtr, uint*, int> NtSuspend;
    public delegate* unmanaged[Stdcall]<IntPtr, void*, nuint, int> NtFlushCache;
    public delegate* unmanaged[Stdcall]<IntPtr, int> NtClose;
    // PVOID RtlAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler).
    public delegate* unmanaged[Stdcall]<uint, nint, nint> RtlAddVectoredExceptionHandler;
    public delegate* unmanaged[Stdcall]<nint, uint> RtlRemoveVectoredExceptionHandler;
}

public static unsafe class BridgeFill
{
    // Explicit bridge field copy instead of unsafe reinterpret cast.
    public static InternalBridge FromSyscallBridge(SyscallBridge* b)
    {
        if (b == null) return default;
        InternalBridge api = default;
        api.NtAllocate = (delegate* unmanaged[Stdcall]<IntPtr, void**, nuint, nuint*, uint, uint, int>)b->NtAllocateVirtualMemory;
        api.NtFree = (delegate* unmanaged[Stdcall]<IntPtr, void**, nuint*, uint, int>)b->NtFreeVirtualMemory;
        api.NtProtect = (delegate* unmanaged[Stdcall]<IntPtr, void**, nuint*, uint, uint*, int>)b->NtProtectVirtualMemory;
        api.NtRead = (delegate* unmanaged[Stdcall]<IntPtr, void*, void*, nuint, nuint*, int>)b->NtReadVirtualMemory;
        api.NtWrite = (delegate* unmanaged[Stdcall]<IntPtr, void*, void*, nuint, nuint*, int>)b->NtWriteVirtualMemory;
        api.NtQueryVirtual = (delegate* unmanaged[Stdcall]<IntPtr, void*, int, void*, nuint, nuint*, int>)b->NtQueryVirtualMemory;
        api.NtMapView = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, void**, nuint, nuint, long*, nuint*, int, uint, uint, int>)b->NtMapViewOfSection;
        api.NtOpenProcess = (delegate* unmanaged[Stdcall]<IntPtr*, uint, void*, void*, int>)b->NtOpenProcess;
        api.NtDuplicateObject = (delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, IntPtr*, uint, uint, uint, int>)b->NtDuplicateObject;
        api.NtQueryInformationProcess = (delegate* unmanaged[Stdcall]<IntPtr, int, void*, uint, uint*, int>)b->NtQueryInformationProcess;
        api.NtQuerySystemInformation = (delegate* unmanaged[Stdcall]<int, void*, uint, uint*, int>)b->NtQuerySystemInformation;
        api.NtQueueApc = (delegate* unmanaged[Stdcall]<IntPtr, void*, void*, void*, void*, int>)b->NtQueueApcThread;
        api.NtGetContext = (delegate* unmanaged[Stdcall]<IntPtr, void*, uint, int>)b->NtGetContextThread;
        api.NtSetContext = (delegate* unmanaged[Stdcall]<IntPtr, void*, uint, int>)b->NtSetContextThread;
        api.NtResume = (delegate* unmanaged[Stdcall]<IntPtr, uint*, int>)b->NtResumeThread;
        api.NtSuspend = (delegate* unmanaged[Stdcall]<IntPtr, uint*, int>)b->NtSuspendThread;
        api.NtFlushCache = (delegate* unmanaged[Stdcall]<IntPtr, void*, nuint, int>)b->NtFlushInstructionCache;
        api.NtClose = (delegate* unmanaged[Stdcall]<IntPtr, int>)b->NtClose;
        api.RtlAddVectoredExceptionHandler = (delegate* unmanaged[Stdcall]<uint, nint, nint>)b->RtlAddVectoredExceptionHandler;
        api.RtlRemoveVectoredExceptionHandler = (delegate* unmanaged[Stdcall]<nint, uint>)b->RtlRemoveVectoredExceptionHandler;
        return api;
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_PROCESS_INFORMATION
{
    public uint NextEntryOffset;
    public uint NumberOfThreads;
    public long WorkingSetPrivateSize;
    public uint HardFaultCount;
    public uint NumberOfThreadsHighWatermark;
    public ulong CycleTime;
    public long CreateTime;
    public long UserTime;
    public long KernelTime;
    public UNICODE_STRING ImageName;
    public int BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
    public uint HandleCount;
    public uint SessionId;
    public UIntPtr UniqueProcessKey;
}

[StructLayout(LayoutKind.Sequential)]
public struct CLIENT_ID
{
    public IntPtr UniqueProcess;
    public IntPtr UniqueThread;
}

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES
{
    public uint Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

[StructLayout(LayoutKind.Sequential)]
public struct LIST_ENTRY
{
    public IntPtr Flink;
    public IntPtr Blink;
}

[StructLayout(LayoutKind.Sequential)]
public struct LDR_DATA_TABLE_ENTRY
{
    public LIST_ENTRY InLoadOrderLinks;
    public LIST_ENTRY InMemoryOrderLinks;
    public LIST_ENTRY InInitializationOrderLinks;
    public IntPtr DllBase;
    public IntPtr EntryPoint;
    public uint SizeOfImage;
    private uint _pad0;
    public UNICODE_STRING FullDllName;
    public UNICODE_STRING BaseDllName;
}

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    public IntPtr Object;
    public UIntPtr UniqueProcessId;
    public UIntPtr HandleValue;
    public uint GrantedAccess;
    public ushort CreatorBackTraceIndex;
    public ushort ObjectTypeIndex;
    public uint HandleAttributes;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_HANDLE_INFORMATION_EX
{
    public nuint NumberOfHandles;  
    public nuint Reserved;       
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_BASIC_INFORMATION
{
    public int ExitStatus;
    public int Reserved0;
    public IntPtr PebBaseAddress;
    public IntPtr AffinityMask;
    public IntPtr BasePriority;
    public UIntPtr UniqueProcessId;
    public UIntPtr InheritedFromUniqueProcessId;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXCEPTION_RECORD
{
    public uint ExceptionCode;
    public uint ExceptionFlags;
    public IntPtr ExceptionRecord;
    public IntPtr ExceptionAddress;
    public uint NumberParameters;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
    public IntPtr[] ExceptionInformation;
}

[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct M128A
{
    public ulong Low;
    public long High;
}

// AMD64 CONTEXT fragment from winnt layout; field order is binary-sensitive.
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct CONTEXT64
{
    public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    public uint ContextFlags;
    public uint MxCsr;
    public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    public uint EFlags;
    public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
    public byte[] FltSave;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
    public M128A[] VectorRegister;
    public ulong VectorControl;
    public ulong DebugControl;
    public ulong LastBranchToRip;
    public ulong LastBranchFromRip;
    public ulong LastExceptionToRip;
    public ulong LastExceptionFromRip;
}