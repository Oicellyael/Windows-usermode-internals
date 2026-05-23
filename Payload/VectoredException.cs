using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Retention;

// Thin wrappers around RtlAddVectoredExceptionHandler / RtlRemoveVectoredExceptionHandler
// (resolved via Core.Api from the syscall bridge — no Win32 DllImport here).
public static unsafe class VectoredException
{
    // EXCEPTION_CONTINUE_SEARCH — let the rest of the chain / debugger handle it.
    public const int ContinueSearch = 0;

    // EXCEPTION_CONTINUE_EXECUTION — resume with the possibly patched context record.
    public const int ContinueExecution = -1;

    // First = 1 → handler runs early in the vectored list (before most others).
    public static IntPtr RegisterFirst(delegate* unmanaged[Stdcall]<EXCEPTION_POINTERS*, int> handler) =>
        Core.Api.RtlAddVectoredExceptionHandler != null
            ? (IntPtr)Core.Api.RtlAddVectoredExceptionHandler(1, (nint)handler)
            : IntPtr.Zero;

    // First = 0 → register as "last" handler.
    public static IntPtr RegisterLast(delegate* unmanaged[Stdcall]<EXCEPTION_POINTERS*, int> handler) =>
        Core.Api.RtlAddVectoredExceptionHandler != null
            ? (IntPtr)Core.Api.RtlAddVectoredExceptionHandler(0, (nint)handler)
            : IntPtr.Zero;

    // RtlRemove returns non-zero on success; handle is the opaque cookie from Add.
    public static bool Remove(IntPtr handle) =>
        handle != IntPtr.Zero && Core.Api.RtlRemoveVectoredExceptionHandler != null
        && Core.Api.RtlRemoveVectoredExceptionHandler((nint)handle) != 0;

    // Stdcall + unmanaged entrypoint required so ntdll can call this like a native VEH.
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    public static int Passthrough(EXCEPTION_POINTERS* _) => ContinueSearch;
}
